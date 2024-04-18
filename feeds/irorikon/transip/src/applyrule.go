package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
	ss "transip/ss"

	pb "github.com/geewan-rd/transip-connecter/proto"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

var (
	relayServer        *pb.ProxyServers
	ssMap              sync.Map
	defaultSSCli       *ss.Client
	defaultTun2socksID = 4096
	tun2socksMap       = make(map[int]*exec.Cmd)
)

func applyRule(proxies *pb.Proxies) error {
	err := resetNetwork()
	if err != nil {
		return fmt.Errorf("reset network: %v", err)
	}
	if len(proxies.ProxyNodes) == 0 || len(proxies.ProxyServers) == 0 {
		log.Printf("No proxy servers or proxy nodes")
		return nil
	}

	relayServer = proxies.ProxyServers[rand.Intn(len(proxies.ProxyServers))]
	log.Printf("Chose relay server: %s:%d", relayServer.Ip, relayServer.Port)
	ciph, err := core.PickCipher(defaultMethd, []byte{}, relayServer.Password)
	if err != nil {
		return fmt.Errorf("pick cipher: %v", err)
	}
	tcpConnecter, udpConnecter := genConnecter(relayServer)
	serverAddr := fmt.Sprintf("%s:%d", relayServer.Ip, relayServer.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %v", err)
	}
	execute("iptables -t mangle -I TRANSIP -m mac --mac-source 2c:f0:5d:a8:d6:2a -j RETURN")
	execute("iptables -t nat -I TRANSIP -m mac --mac-source 2c:f0:5d:a8:d6:2a -j RETURN")
	excludeIps, err := getExcludeTargets()
	if err != nil {
		log.Printf("get exclude targets: %v", err)
	} else {
		for _, ip := range excludeIps {
			execute(fmt.Sprintf("iptables -t mangle -I TRANSIP -d %s -j RETURN", ip))
			execute(fmt.Sprintf("iptables -t nat -I TRANSIP -d %s -j RETURN", ip))
		}
	}
	switch proxies.Mode {
	case pb.ProxyMode_PROXY_MODE_SINGLE:
		if proxies.DefaultProxyNodeId == 0 {
			return fmt.Errorf("default proxy node id is 0")
		}
		log.Printf("Single proxy mode, starting default proxy [%d]", proxies.DefaultProxyNodeId)
		localPort := defaultProxyLocalPort
		redirPort := defaultRdierPort
		localAddr := fmt.Sprintf("0.0.0.0:%d", localPort)
		redirAddr := fmt.Sprintf("0.0.0.0:%d", redirPort)
		defaultSSCli = ss.NewClient(0, defaultUDPBufSize, 10*time.Second)
		defaultSSCli.SetConnecter(tcpConnecter)
		defaultSSCli.SetPcConnecter(udpConnecter)
		defaultSSCli.OutboundID = int(proxies.DefaultProxyNodeId)
		err := defaultSSCli.StartsocksConnLocal(localAddr, ciph.StreamConn)
		if err != nil {
			return fmt.Errorf("start socks conn local: %v", err)
		}
		err = defaultSSCli.StartRedir(redirAddr, ciph.StreamConn)
		if err != nil {
			return fmt.Errorf("start redir: %v", err)
		}
		err = defaultSSCli.UdpSocksLocal(localAddr, udpAddr, ciph.PacketConn)
		if err != nil {
			return fmt.Errorf("udp socks local: %v", err)
		}
		tun_name := "tun_default"
		execute(fmt.Sprintf("ip tuntap add mode tun dev %s", tun_name))
		execute(fmt.Sprintf("ip addr add 10.0.100.1/24 dev %s", tun_name))
		execute(fmt.Sprintf("ip link set %s up", tun_name))
		runTun2socks(defaultTun2socksID, tun_name, localPort)
		execute(fmt.Sprintf("ip route add 0.0.0.0/0 dev %s table %d", tun_name, defaultTun2socksID))
		execute(fmt.Sprintf("ip rule add fwmark %d table %d", defaultTun2socksID, defaultTun2socksID))
		execute(fmt.Sprintf("iptables -t mangle -A TRANSIP -p udp -j MARK --set-mark %d", defaultTun2socksID))
		execute(fmt.Sprintf("iptables -t nat -A TRANSIP -p tcp --j REDIRECT --to-port %d", redirPort))
	case pb.ProxyMode_PROXY_MODE_MULTI:
		var proxyNo = 0
		localPort := localPortBase + proxyNo
		redirPort := redirPortBase + proxyNo
		for _, rule := range proxies.ProxyRules {
			if _, ok := ssMap.Load(rule.ProxyId); !ok {
				proxyNo++
				// 启动 SS
				log.Printf("Starting proxy: %d", rule.ProxyId)
				localAddr := fmt.Sprintf("0.0.0.0:%d", localPort)
				redirAddr := fmt.Sprintf("0.0.0.0:%d", redirPort)
				client := ss.NewClient(0, defaultUDPBufSize, 10*time.Second)
				client.SetConnecter(tcpConnecter)
				client.SetPcConnecter(udpConnecter)
				client.OutboundID = int(rule.ProxyId)
				err = client.StartRedir(redirAddr, ciph.StreamConn)
				if err != nil {
					log.Printf("start redir: %v", err)
					continue
				}
				err = client.StartsocksConnLocal(localAddr, ciph.StreamConn)
				if err != nil {
					log.Printf("start socks conn local: %v", err)
					continue
				}
				err = client.UdpSocksLocal(localAddr, udpAddr, ciph.PacketConn)
				if err != nil {
					log.Printf("udp socks local: %v", err)
					continue
				}
				ssMap.Store(rule.ProxyId, client)
				// 启动tun2socks
				tun_name := fmt.Sprintf("tun_%d", proxyNo)
				execute(fmt.Sprintf("ip tuntap add mode tun dev %s", tun_name))
				execute(fmt.Sprintf("ip addr add 10.0.0.%d/24 dev %s", proxyNo, tun_name))
				execute(fmt.Sprintf("ip link set %s up", tun_name))
				runTun2socks(int(rule.ProxyId), tun_name, localPort)

				// 策略路由
				execute(fmt.Sprintf("ip route add 0.0.0.0/0 dev %s table %d", tun_name, proxyNo))
				execute(fmt.Sprintf("ip rule add fwmark %d table %d", proxyNo, proxyNo))
			}
			// 配置 iptables
			for _, srcIP := range rule.SrcIp {
				re := strings.Split(srcIP, " ")
				if len(re) == 0 {
					continue
				}
				ip := re[0]
				execute(fmt.Sprintf("iptables -t mangle -I TRANSIP -s %s -j RETURN", ip))
				execute(fmt.Sprintf("iptables -t mangle -I TRANSIP -p udp -s %s -j MARK --set-mark %d", ip, proxyNo))
				execute(fmt.Sprintf("iptables -t nat -I TRANSIP -p tcp -s %s -j REDIRECT --to-port %d", ip, redirPort))
			}
			for _, srcMac := range rule.SrcMac {
				re := strings.Split(srcMac, " ")
				if len(re) == 0 {
					continue
				}
				mac := re[0]
				execute(fmt.Sprintf("iptables -t mangle -I TRANSIP -m mac --mac-source %s -j RETURN", mac))
				execute(fmt.Sprintf("iptables -t mangle -I TRANSIP -p udp -m mac --mac-source %s -j MARK --set-mark %d", mac, proxyNo))
				execute(fmt.Sprintf("iptables -t nat -I TRANSIP -p tcp -m mac --mac-source %s -j REDIRECT --to-port %d", mac, redirPort))
			}
		}
		execute("iptables -t mangle -A TRANSIP -p all -j DROP")
	default:
	}

	return nil
}

type delayInfo struct {
	server *pb.ProxyServers
	err    error
	*PingResult
}

func reChooseRelayServer(servers []*pb.ProxyServers) {
	ch := make(chan delayInfo)
	for _, server := range servers {
		go func() {
			re, err := Ping(server.Ip, 10)
			ch <- delayInfo{server, err, re}
		}()
	}
	infos := make([]delayInfo, 0, len(servers))
	for range servers {
		info := <-ch
		if info.err != nil {
			log.Printf("ping %s failed: %v", info.server.Ip, info.err)
			continue
		}
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		log.Printf("all servers are unreachable")
		return
	}
	var chosen *delayInfo
	for _, info := range infos {
		if chosen == nil {
			chosen = &info
			continue
		}
		if info.Loss < chosen.Loss {
			chosen = &info
			continue
		}
		if info.Loss < chosen.Loss {
			chosen = &info
			continue
		}
		if info.AvgRTT < chosen.AvgRTT {
			chosen = &info
		}
	}
	if chosen.server.Ip == relayServer.Ip {
		log.Printf("The current relay server %s is the best", relayServer.Ip)
		return
	}
	log.Printf("Chose relay server: %s:%d", chosen.server.Ip, chosen.server.Port)
	relayServer = chosen.server
	tcpConnecter, udpConnecter := genConnecter(relayServer)
	if defaultSSCli != nil {
		defaultSSCli.SetConnecter(tcpConnecter)
		defaultSSCli.SetPcConnecter(udpConnecter)
	}
	ssMap.Range(func(key, value interface{}) bool {
		client := value.(*ss.Client)
		client.SetConnecter(tcpConnecter)
		client.SetPcConnecter(udpConnecter)
		return true
	})
}

func resetNetwork() error {
	stopAllss()
	stopAllTun2socks()

	lan, err := get_lan_cidr()
	if err != nil {
		return fmt.Errorf("get lan cidr: %v", err)
	}
	execute("killall tun2socks")
	execute("iptables -t mangle -N TRANSIP")
	execute("iptables -t mangle -F TRANSIP")
	execute("iptables -t mangle -D PREROUTING -j TRANSIP")
	execute(fmt.Sprintf("iptables -t nat -D POSTROUTING -p all -s %s ! -d %s -j MASQUERADE", lan, lan))
	execute("iptables -t nat -D POSTROUTING -p all -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE")

	deleteCustomIPRoutes()
	deleteCustomIPRules()
	deleteAllTun()

	execute("iptables -t mangle -A PREROUTING -j TRANSIP")
	execute("iptables -t mangle -A TRANSIP -d 0/8 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 127/8 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 10/8 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 169.254/16 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 172.16/12 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 192.168/16 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 224/4 -j RETURN")
	execute("iptables -t mangle -A TRANSIP -d 240/4 -j RETURN")
	execute(fmt.Sprintf("iptables -t nat -I POSTROUTING -p all -s %s ! -d %s -j MASQUERADE", lan, lan))
	execute("iptables -t nat -I POSTROUTING -p all -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE")

	execute("iptables -t nat -N TRANSIP")
	execute("iptables -t nat -F TRANSIP")
	execute("iptables -t nat -D PREROUTING -j TRANSIP")

	execute("iptables -t nat -I PREROUTING -j TRANSIP")
	execute("iptables -t nat -A TRANSIP -d 0/8 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 127/8 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 10/8 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 169.254/16 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 172.16/12 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 192.168/16 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 224/4 -j RETURN")
	execute("iptables -t nat -A TRANSIP -d 240/4 -j RETURN")

	return nil
}
