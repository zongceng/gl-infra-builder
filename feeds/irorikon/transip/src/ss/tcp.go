package shadowsocks2

import (
	"net"

	"github.com/shadowsocks/go-shadowsocks2/freconn"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type TCPConnecter struct {
	ServerAddr   string
	Stat         *freconn.Stat
	localTCPAddr *net.TCPAddr
}

func (tc *TCPConnecter) Connect() (net.Conn, error) {
	var c net.Conn
	var err error
	if tc.localTCPAddr == nil {
		c, err = net.Dial("tcp", tc.ServerAddr)
	} else {
		serverTCPAddr, e := net.ResolveTCPAddr("tcp4", tc.ServerAddr)
		if e != nil {
			return nil, e
		}
		c, e = net.DialTCP("tcp4", tc.localTCPAddr, serverTCPAddr)
	}
	if err != nil {
		return c, err
	}
	newConn := freconn.UpgradeConn(c)
	newConn.EnableStat(tc.Stat)
	return newConn, nil
}

func (tc *TCPConnecter) ServerHost() string {
	return tc.ServerAddr
}

// Create a TCP tunnel from addr to target via server.
func tcpTun(addr, server, target string, shadow func(net.Conn) net.Conn) {
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		logf("invalid target address %q", target)
		return
	}
	logf("TCP tunnel %s <-> %s <-> %s", addr, server, target)
	tcpLocal(addr, server, shadow, func(net.Conn) (socks.Addr, error) { return tgt, nil })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)
			tgt, err := getAddr(c)
			if err != nil {

				// UDP: keep the connection until disconnect then free the UDP socket
				if err == socks.InfoUDPAssociate {
					buf := make([]byte, 1)
					// block here
					for {
						_, err := c.Read(buf)
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						logf("UDP Associate End.")
						return
					}
				}

				logf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			rc = shadow(rc)

			if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			_, _, err = relay(rc, c)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}
