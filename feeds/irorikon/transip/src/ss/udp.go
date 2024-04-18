package shadowsocks2

import (
	"net"

	"github.com/geewan-rd/transip-relay-server/uot"
	"github.com/xtaci/tcpraw"
)

type UDPConnecter struct {
	ServerAddress string
}

func (c *UDPConnecter) DialPacketConn(localAddr net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenUDP("udp", localAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	return pc, err
}

func (c *UDPConnecter) ServerAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.ServerAddress)
	return addr
}

type UotConnecter struct {
	ServerAddress string
}

func (c *UotConnecter) DialPacketConn(localAddr net.Addr) (net.PacketConn, error) {
	utoc, err := uot.NewClient(c.ServerAddress)
	if err != nil {
		return nil, err
	}
	return utoc, err
}

func (c *UotConnecter) ServerAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.ServerAddress)
	return addr
}

type TcpRawConnecter struct {
	ServerAddress string
}

func (c *TcpRawConnecter) DialPacketConn(localAddr net.Addr) (net.PacketConn, error) {
	pc, err := tcpraw.Dial("tcp", c.ServerAddress)
	return pc, err
}

func (c *TcpRawConnecter) ServerAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.ServerAddress)
	return addr
}
