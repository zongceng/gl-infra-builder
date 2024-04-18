package shadowsocks2

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type Client struct {
	TCPSocksListener net.Listener
	TCPRedirListener net.Listener
	UDPSocksPC       net.PacketConn
	udpTimeout       time.Duration
	udpBufSize       int
	udpServerAddr    net.Addr
	Connecter        Connecter
	upgradeConn      shadowUpgradeConn
	PcConnecter      PcConnecter
	upgradePc        shadowUpgradePacketConn
	connecterLock    sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	OutboundID       int
}

func logf(f string, v ...interface{}) {
	log.Printf(f, v...)
}

func NewClient(maxConnCount, UDPBufSize int, UDPTimeout time.Duration) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		udpTimeout: UDPTimeout,
		udpBufSize: UDPBufSize,
		ctx:        ctx,
		cancel:     cancel,
	}
	return c
}

type Connecter interface {
	Connect() (net.Conn, error)
	ServerHost() string
}

func (c *Client) SetConnecter(connecter Connecter) {
	c.connecterLock.Lock()
	defer c.connecterLock.Unlock()
	c.Connecter = connecter
}

func (c *Client) GetConnecter() Connecter {
	c.connecterLock.RLock()
	defer c.connecterLock.RUnlock()
	return c.Connecter
}

func (c *Client) SetPcConnecter(pcConnecter PcConnecter) {
	c.connecterLock.Lock()
	defer c.connecterLock.Unlock()
	c.PcConnecter = pcConnecter
}

func (c *Client) GetPcConnecter() PcConnecter {
	c.connecterLock.RLock()
	defer c.connecterLock.RUnlock()
	return c.PcConnecter
}

type shadowUpgradeConn func(net.Conn) net.Conn
type shadowUpgradePacketConn func(net.PacketConn) net.PacketConn

func (c *Client) StartRedir(addr string, shadow shadowUpgradeConn) error {
	logf("REDIR proxy %s <-> %s", addr, c.Connecter.ServerHost())
	var err error
	c.TCPRedirListener, err = net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return err
	}
	c.upgradeConn = shadow
	go func() {
		for {
			lc, err := c.TCPRedirListener.Accept()
			if err != nil {
				logf("failed to accept: %s", err)
				if c.ctx.Err() != nil {
					return
				}
				continue
			}
			lc.(*net.TCPConn).SetKeepAlive(true)
			go c.handleConn(lc, func(conn net.Conn) (socks.Addr, error) { return getOrigDst(conn, false) })
		}
	}()

	return nil
}

func (c *Client) StartsocksConnLocal(addr string, shadow shadowUpgradeConn) error {
	logf("SOCKS proxy %s <-> %s", addr, c.Connecter.ServerHost())
	var err error
	c.TCPSocksListener, err = net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return err
	}
	c.upgradeConn = shadow
	go func() {
		for {
			lc, err := c.TCPSocksListener.Accept()
			if err != nil {
				logf("failed to accept: %s", err)
				if c.ctx.Err() != nil {
					return
				}
				continue
			}
			lc.(*net.TCPConn).SetKeepAlive(true)
			go c.handleConn(lc, func(conn net.Conn) (socks.Addr, error) { return socks.Handshake(conn) })
		}
	}()

	return nil
}

func (c *Client) handleConn(lc net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	defer lc.Close()
	tgt, err := getAddr(lc)
	if err != nil {
		// UDP: keep the connection until disconnect then free the UDP socket
		if err == socks.InfoUDPAssociate {
			// logf("UDP Associate Start:%s.", lc.RemoteAddr())
			buf := make([]byte, 1)
			// block here
			for {
				_, err := lc.Read(buf)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				if err == nil {
					continue
				}
				// logf("UDP Associate End:%s.", err)
				return
			}
		}
		logf("failed to get target address: %v", err)
		return
	}
	connecter := c.GetConnecter()
	rc, err := connecter.Connect()
	if err != nil {
		logf("Connect to %s failed: %s", connecter.ServerHost(), err)
		return
	}
	defer rc.Close()

	remoteConn := c.upgradeConn(rc)
	if c.OutboundID != 0 {
		transipInfoBytes := make([]byte, 4)
		binary.BigEndian.PutUint16(transipInfoBytes[:2], uint16(c.OutboundID))
		if _, err = remoteConn.Write(transipInfoBytes); err != nil {
			logf("failed to send transip Info: %v", err)
			return
		}
	}
	if _, err = remoteConn.Write(tgt); err != nil {
		logf("failed to send target address: %v", err)
		return
	}

	// logf("proxy %s <-> %s <-> %s", lc.RemoteAddr(), connecter.ServerHost(), tgt)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		remoteConn.SetDeadline(time.Now())
	}()
	_, _, err = relay(remoteConn, lc)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logf("relay error: %v", err)
	}
}

type PcConnecter interface {
	DialPacketConn(localAddr net.Addr) (net.PacketConn, error)
	ServerAddr() net.Addr
}

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func (c *Client) UdpSocksLocal(laddr string, server net.Addr, shadow shadowUpgradePacketConn) error {
	var err error
	c.UDPSocksPC, err = net.ListenPacket("udp", laddr)
	if err != nil {
		logf("UDP local listen error: %v", err)
		return err
	}
	c.upgradePc = shadow
	c.udpServerAddr = server
	go func() {
		defer c.UDPSocksPC.Close()

		nm := newNATmap(udpTimeout)
		buf := make([]byte, udpBufSize)

		for {
			select {
			case <-c.ctx.Done():
				logf("exit udp\n")
				return
			default:
				// 原数据从不发送接收到报文的前三个字节,但是transip要在数据前加上4个字节,所以跳过一个字节开始接收
				n, raddr, err := c.UDPSocksPC.ReadFrom(buf[1:])
				if err != nil {
					logf("UDP local read error: %v", err)
					continue
				}
				pc := nm.Get(raddr.String())
				pcConnecter := c.GetPcConnecter()
				if pc == nil {
					pc, err = pcConnecter.DialPacketConn(&net.UDPAddr{})
					if err != nil {
						logf("UDP local listen error: %v", err)
						continue
					}
					// logf("UDP socks tunnel %s <-> %s <-> %s", laddr, c.udpServerAddr, socks.Addr(buf[4:]))
					pc = c.upgradePc(pc)
					nm.Add(raddr, c.UDPSocksPC, pc, socksClient)
				}
				transipInfoBytes := make([]byte, 4)
				binary.BigEndian.PutUint16(transipInfoBytes[:2], uint16(c.OutboundID))
				copy(buf, transipInfoBytes)
				_, err = pc.WriteTo(buf[:n+1], pcConnecter.ServerAddr())
				if err != nil {
					logf("UDP local write error: %v", err)
					continue
				}
			}
		}
	}()
	return nil
}

func (c *Client) Stop() error {
	logf("stopping ss")
	c.cancel()
	if c.TCPSocksListener != nil {
		err := c.TCPSocksListener.Close()
		if err != nil {
			logf("close tcp listener failed: %s", err)
			return err
		}
	}
	if c.TCPRedirListener != nil {
		err := c.TCPRedirListener.Close()
		if err != nil {
			logf("close tcp redir listener failed: %s", err)
			return err
		}
	}
	if c.UDPSocksPC != nil {
		err := c.UDPSocksPC.Close()
		if err != nil {
			logf("stop ss err: %s", err)
			return errors.New("stop ss err: " + err.Error())
		}
	}
	return nil
}
