package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	"github.com/leviathan1995/Trident/encryption"
	"github.com/leviathan1995/Trident/service"
)

type server struct {
	*service.Service
	tlsPort int
}

func NewServer(addr, password string, tlsPort int) *server {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	c := encryption.NewCipher([]byte(password))

	return &server{
		&service.Service{
			Cipher: c,
			ListenAddr: tcpAddr,
		},
		tlsPort,
	}
}

func (s *server) Listen() {
	listen, err := net.ListenTCP("tcp", s.ListenAddr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Server启动成功,监听在 %s:%d, 密码: %s", s.ListenAddr.IP, s.ListenAddr.Port, s.Cipher.Password)
	defer listen.Close()

	for {
		userConn, err := listen.AcceptTCP()
		if err != nil {
			log.Fatalf("%s", err.Error())
		}
		userConn.SetLinger(0)
		go s.handleTCPConn(userConn)
	}
}

func (s *server) ListenTLS() error {
	log.Printf("Server TLS address: %s:%d", s.ListenAddr.IP.String(), s.tlsPort)

	cert, err := tls.LoadX509KeyPair("/etc/server.pem", "/etc/server.key")
	if err != nil {
		log.Println(err)
		return err
	}

	certBytes, err := ioutil.ReadFile("/etc/client.pem")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.IP.String() + ":" + strconv.Itoa(s.tlsPort), config)
	if err != nil {
		return err
	} else {
		log.Printf("Server TLS listen at %s:%d successed.",s.ListenAddr.IP.String(), s.tlsPort)
	}
	defer listener.Close()

	for {
		cliConn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go s.handleTLSConn(cliConn)
	}
}

func (s *server) handleTLSConn(cliConn net.Conn) {
	defer cliConn.Close()

	dstAddr, errParse := s.ParseSOCKS5FromTLS(cliConn)
	if errParse != nil {
		log.Printf("Parse SOCKS5 failed: %s", errParse.Error())
		return
	}

	/* Try to direct connect to the destination sever. */
	dstConn, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("Connect to %s:%d failed.", dstAddr.IP.String(), dstAddr.Port)
		return
	} else {
		log.Printf("Connect to the destination address success %s:%d.", dstAddr.IP, dstAddr.Port)
	}

	defer dstConn.Close()
	_ = dstConn.SetLinger(0)

	/* Connect to the destination sever success. */
	errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if errWrite != nil {
		log.Println("Server reply the SOCKS5 protocol failed at the second stage.")
		return
	}

	go func() {
		errTransfer := s.TransferToTCP(cliConn, dstConn)
		if errTransfer != nil {
			log.Println(errTransfer.Error())
		}
	}()
	err = s.TransferToTLS(dstConn, cliConn)
}

func (s *server) handleTCPConn(userConn *net.TCPConn) {
	defer userConn.Close()
	/*
	 *  RFC 1928 - IETF
	 * https://www.ietf.org/rfc/rfc1928.txt
	 */

	/*	We already move the SOCKS5 parsing to the client, but if the client can't directly
	 *  connect to the destination address, the client must send the user the last request to the
	 *  proxy knows what address to connect, and if connect the destination success, we
	 *  also need to notify client.
	 */

	/** Get the connect command and the destination address */
	buf := make([]byte, service.BUFFS)
	n, err := s.DecodeFrom(buf, userConn)
	if err != nil {
		return
	}

	if buf[1] != 0x01 {	/** Only support connect */
		return
	}

	/** Parse destination addr and port */
	var desIP []byte
	switch buf[3] {
	case 0x01:
		desIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return
		}
		desIP = ipAddr.IP
	case 0x04:
		desIP = buf[4 : 4+net.IPv6len]
	default:
		return
	}
	dstPort := buf[n-2 : n]
	dstAddr := &net.TCPAddr{
		IP:   desIP,
		Port: int(binary.BigEndian.Uint16(dstPort)),
	}

	/** Step4: connect to the destination server and send a reply to client */
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("Connect to destination addr %s failed", dstAddr.String())
		return
	} else {
		defer dstServer.Close()
		dstServer.SetLinger(0)
		/** If connect to the dst addr success, we need to notify client */
		_, errWrite := s.EncodeTo([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, userConn)
		if errWrite != nil {
			return
		}
	}

	log.Printf("Connect to destination addr %s", dstAddr.String())

	go func() {
		err := s.TransferForEncode(dstServer, userConn)
		if err != nil {
			userConn.Close()
			dstServer.Close()
		}
	}()

	_ = s.TransferForDecode(userConn, dstServer)
}
