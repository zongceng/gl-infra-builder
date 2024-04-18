package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingResult struct {
	AvgRTT time.Duration
	Loss   float64
}

func Ping(address string, count int) (*PingResult, error) {
	// 解析IP地址
	dst, err := net.ResolveIPAddr("ip4", address)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve IP address: %v", err)
	}

	// 创建ICMP连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("Failed to listen on ICMP: %v", err)
	}
	defer conn.Close()

	var sent, received int
	var totalRTT time.Duration

	// 发送指定次数的ICMP Echo请求
	for i := 0; i < count; i++ {
		// 创建ICMP Echo请求消息
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: i + 1,
				Data: []byte("HELLO-R-U-THERE"),
			},
		}
		binaryMsg, err := msg.Marshal(nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal ICMP message: %v", err)
		}

		// 发送消息
		start := time.Now()
		if _, err := conn.WriteTo(binaryMsg, dst); err != nil {
			return nil, fmt.Errorf("Failed to write ICMP message: %v", err)
		}
		sent++

		// 设置接收超时
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		// 接收响应
		reply := make([]byte, 1500)
		_, _, err = conn.ReadFrom(reply)
		if err != nil {
			continue // 超时或其他错误，不计入received
		}
		received++

		rtt := time.Since(start)
		totalRTT += rtt
	}

	// 计算平均延迟和丢包率
	avgRTT := totalRTT / time.Duration(received)
	loss := float64(sent-received) / float64(sent) * 100

	return &PingResult{
		AvgRTT: avgRTT,
		Loss:   loss,
	}, nil
}
