package client

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Trident/service"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

const maxBlock = 5000

type block struct {
	item map[string]int
	mu    *sync.RWMutex
}

type client struct {
	*service.Service
	*block
	forceProxy []string
}

func NewClient(server []string, listen, password string, urls []string) *client {
	listenAddr, _ := net.ResolveTCPAddr("tcp", listen)

	var serverAddrs []*net.TCPAddr
	for _, proxy := range server {
		addr, _ := net.ResolveTCPAddr("tcp", proxy)
		serverAddrs = append(serverAddrs, addr)
	}
	return &client{
		&service.Service{
			ListenAddr:  listenAddr,
			ServerAddrs: serverAddrs,
			StableProxy: serverAddrs[0],
			PassWord:    []byte(password),
		},
		&block{
			mu:		&sync.RWMutex{},
			item: 	make(map[string]int),
			},
			urls,
	}
}

func (c *client) Listen() error {
	for _, proxy := range c.ServerAddrs {
		log.Printf("Server监听地址: %s:%d", proxy.IP, proxy.Port)
	}
	log.Printf("默认Server监听地址: %s:%d", c.Service.StableProxy.IP, c.Service.StableProxy.Port)

	listener, err := net.ListenTCP("tcp", c.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("Client启动成功, 监听地址: %s:%d, 密码: %s", c.ListenAddr.IP, c.ListenAddr.Port, c.PassWord)


	defer listener.Close()

	for {
		userConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		/* Discard any unsent or unacknowledged data. */
		userConn.SetLinger(0)
		go c.handleConn(userConn)
	}
}

var proxyPool = make(chan *kcp.UDPSession, 10)

func init() {
	go func() {
		for range time.Tick(5 * time.Second) {
			p := <-proxyPool	/* Discard the idle connection */
			p.Close()
		}
	}()
}

func (c *client) newProxyConn() (*kcp.UDPSession, error) {
	if len(proxyPool) < 10 {
		go func() {
			for i := 0; i < 2; i++ {
				proxy, err := c.DialServer()
				if err != nil {
					log.Println(err)
					return
				}
				proxyPool <- proxy
			}
		}()
	}

	select {
	case pc := <-proxyPool:
		return pc, nil
	case <-time.After(100 * time.Millisecond):
		return c.DialServer()
	}
}

func (c *client) directDial(userConn *net.TCPConn, dstAddr *net.TCPAddr) (*net.TCPConn, error){
	conn, errDial := net.DialTimeout("tcp", dstAddr.String(), time.Millisecond * 300)

	if errDial != nil {
		return &net.TCPConn{}, errDial
	} else {
		defer conn.Close()
		dstConn, errDialTCP := net.DialTCP("tcp", nil, dstAddr)
		if errDialTCP != nil {
			return &net.TCPConn{}, errDial
		} else {
			dstConn.SetLinger(0)
			/* If connect to the dst addr success, we need to notify client. */
			errDialTCP = c.CustomWrite(userConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10)
		}
		return dstConn, errDialTCP
	}
}

func (c *client) DialServer() (*kcp.UDPSession, error) {
	key := pbkdf2.Key([]byte(c.PassWord), []byte(c.PassWord), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	serverConn, err := kcp.DialWithOptions(c.StableProxy.String(), block, 0, 0)
	if err != nil {
		log.Printf("连接到远程服务器 %s 失败:%s", c.StableProxy.String(), err)

		/** Try to connect the other proxies **/
		for _, proxy := range c.ServerAddrs {
			log.Printf("尝试其他远程服务器: %s", proxy.String())
			serverConn, err := kcp.DialWithOptions(c.StableProxy.String(), block, 10, 3)
			if err == nil {
				c.StableProxy = proxy
				return serverConn, nil

			}
		}
		return nil, errors.New(fmt.Sprintf("所有远程服务器连接均失败"))
	}
	return serverConn, nil
}

func (c *client) directConnect(userConn *net.TCPConn, dstConn *net.TCPConn) {
	go func() {
		err := c.Transfer(userConn, dstConn)
		if err != nil {
			userConn.Close()
			dstConn.Close()
		}
	}()
	c.Transfer(dstConn, userConn)
}

func (c *client) searchBlockList(ip string) bool {
	c.block.mu.RLock()
	defer c.block.mu.RUnlock()

	if _, ok := c.block.item[ip]; ok {
		return true
	} else{
		return false
	}
}

func (c *client) addBlockList(ip string) {
	c.block.mu.Lock()
	defer c.block.mu.Unlock()

	if len(c.block.item) > maxBlock {
		for ip := range c.block.item {
			delete(c.block.item, ip)
			break
		}
	}
	c.block.item[ip] = 1
}

func (c *client) tryProxy(userConn *net.TCPConn, lastUserRequest []byte) {
	proxy, err := c.newProxyConn()
	if err != nil {
		log.Println(err)
		proxy, err = c.newProxyConn()
		if err != nil {
			log.Println(err)
			return
		}
	}
	defer proxy.Close()

	errWrite := c.KCPWrite(proxy, lastUserRequest)
	if errWrite != nil {
		return
	}

	go func() {
		err := c.TransferToKCP(userConn, proxy)
		if err != nil {
			userConn.Close()
			proxy.Close()
		}
	}()
	c.TransferToTCP(proxy, userConn)
}

func (c *client) handleConn(userConn *net.TCPConn) {
	defer userConn.Close()

	/*  Why the use lastUserRequest?
	 *  If we can not direct connect to the destination address, We need to forward
	 *  the last data package to the server.
	 */
	dstAddr, lastUserRequest, errParse := c.ParseSOCKS5(userConn)
	if errParse != nil {
		log.Printf(errParse.Error())
		return
	}

	block := c.searchBlockList(dstAddr.IP.String())
	if block {
		log.Printf("Can't directly connect to %s, Try to use Proxy", dstAddr.String())
		c.tryProxy(userConn, lastUserRequest)
	} else {
		for _, ip := range c.forceProxy {
			if ip == dstAddr.IP.String() {
				go c.addBlockList(dstAddr.IP.String())
				c.tryProxy(userConn, lastUserRequest)
				return
			}
		}

		dstConn, errDirect := c.directDial(userConn, dstAddr)
		if errDirect != nil {
			log.Printf("Can't directly connect to %s, Try to use Proxy and put it into IP blacklist", dstAddr.String())
			go c.addBlockList(dstAddr.IP.String())
			c.tryProxy(userConn, lastUserRequest)
		} else {
			log.Printf("Directly connect to %s", dstAddr.String())
			c.directConnect(userConn, dstConn)
		}
	}
}
