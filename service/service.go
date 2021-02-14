package service

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const BUFFS = 1024 * 16

type Service struct {
	ListenAddr  *net.TCPAddr
	ServerAdders []*net.TCPAddr
	StableProxy *net.TCPAddr
}

func (s *Service) TLSWrite(conn net.Conn, buf []byte) error {
	nWrite := 0
	nBuffer := len(buf)
	for nWrite < nBuffer {
		n, errWrite := conn.Write(buf[nWrite:])
		if errWrite != nil {
			return errWrite
		}
		nWrite += n
	}
	return nil
}

func (s *Service) DialSrv() (*net.TCPConn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	remoteConn, err := d.Dial("tcp", s.StableProxy.String())
	if err != nil {
		log.Printf("Connect to the server %s faield:%s", s.StableProxy.String(), err)

		/** Try to connect the other proxies **/
		for _, srv := range s.ServerAdders {
			log.Printf("Try to connect other server: %s", srv.String())
			remoteConn, err := d.Dial("tcp", srv.String())
			if err == nil {
				s.StableProxy = srv
				tcpConn, _ := remoteConn.(*net.TCPConn)
				return tcpConn, nil

			}
		}
		return nil, errors.New(fmt.Sprintf("All of server connected failed."))
	}
	log.Printf("Connecto to the server %s successfully.", s.StableProxy.String())
	tcpConn, _ := remoteConn.(*net.TCPConn)
	return tcpConn, nil
}

func (s *Service) TransferForEncode(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFS)

	for {
		nRead, errRead := srcConn.Read(buf)
		if errRead != nil {
			return errRead
		}
		if nRead > 0 {
			_, errWrite := s.EncodeTo(buf[0:nRead], dstConn)
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) TransferForDecode(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFS)

	for {
		nRead, errRead := s.DecodeFrom(buf, srcConn)
		if errRead != nil {
			return errRead
		}

		if nRead > 0 {
			_, errWrite := dstConn.Write(buf[0 : nRead])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

/** Encode data */
func (s *Service) EncodeTo(src []byte, dstConn *net.TCPConn) (n int, err error) {
	encrypted := make([]byte, len(src))
	for i, bit := range src {
		encrypted[i] = ^bit
	}

	return dstConn.Write(encrypted)
}

/** Decode data */
func (s *Service) DecodeFrom(src []byte, srcConn *net.TCPConn) (n int, err error) {
	encrypted := make([]byte, BUFFS)
	nRead, errRead := srcConn.Read(encrypted)
	if errRead != nil {
		return nRead, errRead
	}

	for i, bit := range encrypted {
		src[i] = ^bit
	}

	return nRead, nil
}

func (s *Service) Transfer(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFS)
	for {
		readCount, errRead := srcConn.Read(buf)
		if errRead != nil {
			return errRead
		}
		if readCount > 0 {
			_, errWrite := dstConn.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) TransferToTCP(cliConn net.Conn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFS)
	for {
		nRead, err := cliConn.Read(buf)
		if err != nil {
			return err
		}
		if nRead > 0 {
			_, errWrite := dstConn.Write(buf[0 : nRead])
			if err != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) TransferToTLS(dstConn *net.TCPConn, srcConn net.Conn) error {
	buf := make([]byte, BUFFS)
	for {
		nRead, errRead := dstConn.Read(buf)
		if errRead != nil {
			return errRead
		}
		if nRead > 0 {
			errWrite := s.TLSWrite(srcConn, buf[0 : nRead])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) ParseSOCKS5(userConn *net.TCPConn) (*net.TCPAddr, []byte, error) {
	buf := make([]byte, BUFFS)

	readCount, errRead := userConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, nil, errors.New("Read SOCKS5 failed at the first stage.")
	}

	if readCount > 0 {
		if buf[0] != 0x05 {
			/** Version Number */
			return &net.TCPAddr{}, nil, errors.New("Only Support SOCKS5")
		} else {
			/** [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			_, errWrite := userConn.Write([]byte{0x05, 0x00})
			if errWrite != nil {
				return &net.TCPAddr{}, nil, errors.New("Response SOCKS5 failed at the first stage.")
			}
		}
	}

	readCount, errRead = userConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, nil, errors.New("Read SOCKS5 failed at the second stage.")
	}
	if readCount > 0 {
		if buf[1] != 0x01 {
			/** Only support CONNECT method */
			return &net.TCPAddr{}, nil, errors.New("Only support CONNECT and UDP ASSOCIATE method.")
		}

		var desIP []byte
		switch buf[3] { /** checking ATYPE */
		case 0x01: /* IPv4 */
			desIP = buf[4 : 4+net.IPv4len]
		case 0x03: /** DOMAINNAME */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:readCount-2]))
			if err != nil {
				return &net.TCPAddr{}, nil, errors.New("Parse IP failed")
			}
			desIP = ipAddr.IP
		case 0x04: /** IPV6 */
			desIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, nil, errors.New("The Wrong DST.ADDR and DST.PORT")
		}
		dstPort := buf[readCount-2 : readCount]
		dstAddr := &net.TCPAddr{
			IP:   desIP,
			Port: int(binary.BigEndian.Uint16(dstPort)),
		}

		return dstAddr, buf[:readCount], errRead
	}
	return &net.TCPAddr{}, nil, errRead
}

func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (*net.TCPAddr, error) {
	buf := make([]byte, BUFFS)

	nRead, errRead := cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("Read SOCKS5 failed at the first stage.")
	}
	if nRead > 0 {
		if buf[0] != 0x05 {
			/* Version Number */
			return &net.TCPAddr{}, errors.New("Only support SOCKS5 protocol.")
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00})
			if errWrite != nil {
				return &net.TCPAddr{}, errors.New("Response SOCKS5 failed at the first stage.")
			}
		}
	}

	nRead, errRead = cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("Read SOCKS5 failed at the second stage.")
	}
	if nRead > 0 {
		if buf[1] != 0x01 {
			/* Only support CONNECT method */
			return &net.TCPAddr{}, errors.New("Only support CONNECT method.")
		}

		var dstIP []byte
		switch buf[3] { /* checking ATYPE */
		case 0x01: /* IPv4 */
			dstIP = buf[4 : 4+net.IPv4len]
		case 0x03: /* DOMAINNAME */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:nRead-2]))
			if err != nil {
				return &net.TCPAddr{}, errors.New("Parse IP from DomainName failed.")
			}
			dstIP = ipAddr.IP
		case 0x04: /* IPV6 */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, errors.New("Wrong DST.ADDR and DST.PORT")
		}
		dstPort := buf[nRead-2 : nRead]

		if buf[1] == 0x01 {
			/* TCP over SOCKS5 */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}
			return dstAddr, errRead
		} else {
			log.Println("Only support CONNECT method.")
			return &net.TCPAddr{}, errRead
		}
	}
	return &net.TCPAddr{}, errRead
}