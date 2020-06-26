package service

import (
	"encoding/binary"
	"errors"
	"github.com/xtaci/kcp-go/v5"
	"io"
	"net"
)

const BUFFSIZE = 1024 * 1

type Service struct {
	ListenAddr  *net.TCPAddr
	ServerAddrs []*net.TCPAddr
	StableProxy *net.TCPAddr
	PassWord    []byte
}

func (s *Service) KCPRead(conn *kcp.UDPSession, buf []byte) (n int, err error) {
	nRead, errRead := conn.Read(buf)
	return nRead, errRead
}

func (s *Service) KCPWrite(conn *kcp.UDPSession, buf []byte) (err error) {
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

func (s *Service) TCPRead(conn *net.TCPConn, buf []byte) (n int, err error) {
	nRead, errRead := conn.Read(buf)
	return nRead, errRead
}

func (s *Service) TCPWrite(conn *net.TCPConn, buf []byte) (err error) {
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

func (s *Service) TransferToTCP(kcp *kcp.UDPSession, tcp *net.TCPConn) error {
	buf := make([]byte, BUFFSIZE)

	for {
		readCount, errRead := s.KCPRead(kcp, buf)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			errWrite := s.TCPWrite(tcp, buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}


func (s *Service) TransferToKCP(tcp *net.TCPConn, kcp *kcp.UDPSession) error {
	buf := make([]byte, BUFFSIZE)

	for {
		readCount, errRead := s.TCPRead(tcp, buf)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			errWrite := s.KCPWrite(kcp, buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}


func (s *Service) Transfer(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFSIZE * 2)
	for {
		readCount, errRead := srcConn.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			_, errWrite := dstConn.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) CustomRead(userConn *net.TCPConn, buf [] byte) (int, error) {
	readCount, errRead := userConn.Read(buf)
	if errRead != nil {
		if errRead != io.EOF {
			return readCount, nil
		} else {
			return readCount, errRead
		}
	}
	return readCount, nil
}

func (s *Service) CustomWrite(userConn *net.TCPConn, buf [] byte, bufLen int) error {
	writeCount, errWrite := userConn.Write(buf)
	if errWrite != nil {
		return errWrite
	}
	if bufLen != writeCount {
		return io.ErrShortWrite
	}
	return nil
}

func (s *Service) ParseSOCKS5(userConn *net.TCPConn) (*net.TCPAddr, []byte, error){
	buf := make([]byte, BUFFSIZE)

	readCount, errRead := s.CustomRead(userConn, buf)
	if readCount > 0 && errRead == nil {
		if buf[0] != 0x05 {
			/** Version Number */
			return &net.TCPAddr{}, nil, errors.New("Only Support SOCKS5")
		} else {
			/** [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.CustomWrite(userConn, []byte{0x05, 0x00}, 2)
			if errWrite != nil {
				return &net.TCPAddr{}, nil, errors.New("Response SOCKS5 failed at the first stage.")
			}
		}
	}

	readCount, errRead = s.CustomRead(userConn, buf)
	if readCount > 0 && errRead == nil {
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
			return &net.TCPAddr{}, nil, errors.New("Wrong DST.ADDR and DST.PORT")
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
