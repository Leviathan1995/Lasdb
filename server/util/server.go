package server

import (
	"crypto/sha1"
	"encoding/binary"
	"log"
	"net"

	"github.com/Trident/service"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

type server struct {
	*service.Service
}

func NewServer(addr, password string) *server {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	return &server{
		&service.Service{
			PassWord  : []byte(password),
			ListenAddr: tcpAddr,
		},
	}
}

func (s *server) Listen() {
	key := pbkdf2.Key(s.PassWord, s.PassWord, 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)

	if listener, err := kcp.ListenWithOptions(s.ListenAddr.String(), block, 0, 0); err == nil {
		log.Printf("Server启动成功,监听在 %s:%d, 密码: %s", s.ListenAddr.IP, s.ListenAddr.Port, s.PassWord)
		for {
			cliConn, err := listener.AcceptKCP()
			if err != nil {
				log.Fatal(err)
			}
			go s.handleCli(cliConn)
		}
	} else {
		log.Fatal(err)
	}
}

func (s *server) handleCli(cliConn *kcp.UDPSession) {
	defer cliConn.Close()
	/*
	 *  RFC 1928 - IETF
	 * https://www.ietf.org/rfc/rfc1928.txt
	 */

	/*	We already remove SOCKS5 parsing to the client, but if the client can't directly
	 *  connect to the destination address, the client must send the user the last request to the
	 *  proxy knows what address to connect, and if connect the destination success, we
	 *  also need to notify client.
	 */

	/* Get the connect command and the destination address */
	buf := make([]byte, service.BUFFSIZE)
	n, err := s.KCPRead(cliConn, buf)
	if err != nil {
		return
	}

	if buf[1] != 0x01 {	/** Only support connect */
		return
	}

	/* Parse destination addr and port */
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

	/* Step4: connect to the destination server and send a reply to client */
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("Connect to destination addr %s failed", dstAddr.String())
		return
	} else {
		defer dstServer.Close()
		dstServer.SetLinger(0)
		/* If connect to the dst addr success, we need to notify client */
		errWrite := s.KCPWrite(cliConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		if errWrite != nil {
			return
		}
	}

	log.Printf("Connect to destination addr %s", dstAddr.String())

	go func() {
		err := s.TransferToKCP(dstServer, cliConn)
		if err != nil {
			cliConn.Close()
			dstServer.Close()
		}
	}()

	s.TransferToTCP(cliConn, dstServer)
}
