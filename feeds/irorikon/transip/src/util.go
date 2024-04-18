package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	ss "transip/ss"

	"github.com/digineo/go-uci"
	pb "github.com/geewan-rd/transip-connecter/proto"
)

func getUciInfo(name string) (string, error) {
	err := uci.LoadConfig("transip", true)
	if err != nil {
		return "", fmt.Errorf("failed to load uci config: %v", err)
	}
	values, ok := uci.Get("transip", "@info[0]", name)
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("no %s found", name)
	}
	return values[0], nil
}

func getExcludeTargets() ([]string, error) {
	values, ok := uci.Get("transip", "@info[0]", "exclude_dst")
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("no exclude_targets found")
	}
	return values, nil

}

type clientInfo struct {
	Mac  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func saveUci(name, value string) error {
	if name == "" || value == "" {
		return fmt.Errorf("name or value is empty")
	}
	uci.Set("transip", "@info[0]", name, value)
	return uci.Commit()
}

func getAllClientInfo() ([]clientInfo, string, error) {
	data, err := os.ReadFile("/tmp/dhcp.leases")
	if err != nil {
		return nil, "", err
	}
	hash := md5.Sum(data)
	md5String := hex.EncodeToString(hash[:])
	clients := make([]clientInfo, 0)
	for _, line := range strings.Split(string(data), "\n") {
		re := strings.Split(line, " ")
		if len(re) < 4 {
			continue
		}
		clients = append(clients, clientInfo{
			Mac:  re[1],
			IP:   re[2],
			Name: re[3],
		})
	}
	return clients, md5String, nil
}

func GetUUID() (string, error) {
	deviceCode, err := GetNradioDeviceCode()
	if err == nil && deviceCode != "" {
		return deviceCode, nil
	}
	log.Printf("get device code failed: %v", err)
	lan1Mac, err := GetNICMACAddress("lan1")
	if err == nil && lan1Mac != "" {
		return lan1Mac, nil
	}
	log.Printf("get eth0 mac failed: %v", err)
	eth0Mac, err := GetNICMACAddress("eth0")
	if err == nil && eth0Mac != "" {
		return eth0Mac, nil
	}
	return "", fmt.Errorf("get uuid failed")
}

func GetNradioDeviceCode() (string, error) {
	values, ok := uci.Get("oem", "board", "device_code")
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("no device_code found")
	}
	return values[0], nil
}

func GetNICMACAddress(name string) (string, error) {
	cmd := exec.Command("/bin/ash", "-c", fmt.Sprintf("ip link show %s | grep link/ether | awk '{print $2}'", name))
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out.String()), nil
}

func execute(cmdStr string) string {
	fmt.Printf(cmdStr + "\n")
	cmd := exec.Command("/bin/ash", "-c", cmdStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Print(err.Error() + "\n")
		return err.Error()
	}
	fmt.Printf(out.String() + "\n")
	return out.String()
}

func maskToCIDR(netmask string) int {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0
	}

	ip = ip.To4()
	if ip == nil {
		return 0
	}
	ones, _ := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3]).Size()
	return ones
}

func get_lan_cidr() (string, error) {
	values, ok := uci.Get("network", "lan", "ipaddr")
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("no lan ipaddr found")
	}
	ipaddr := values[0]
	values, ok = uci.Get("network", "lan", "netmask")
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("no lan netmask found")
	}
	netmask := values[0]

	cidr := maskToCIDR(netmask)
	return fmt.Sprintf("%s/%d", ipaddr, cidr), nil
}

// deleteCustomIPRules 删除非默认的IP规则
func deleteCustomIPRules() {
	cmd := exec.Command("ip", "rule")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Failed to execute command:", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	ruleRegex := regexp.MustCompile(`^(\d+):`)
	for scanner.Scan() {
		rule := scanner.Text()
		if !strings.Contains(rule, "lookup main") && !strings.Contains(rule, "lookup default") && !strings.Contains(rule, "lookup local") {
			matches := ruleRegex.FindStringSubmatch(rule)
			if len(matches) > 1 {
				rulePriority := matches[1]
				delCmd := exec.Command("ip", "rule", "del", "prio", rulePriority)
				if err := delCmd.Run(); err == nil {
					fmt.Println("Deleted rule with priority", rulePriority)
				}
			}
		}
	}
}

// deleteCustomIPRoutes 删除非默认的IP路由
func deleteCustomIPRoutes() {
	cmd := exec.Command("ip", "route", "show", "table", "all")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Failed to execute command:", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	tableRegex := regexp.MustCompile(`table (\S+)`)
	for scanner.Scan() {
		route := scanner.Text()
		if strings.Contains(route, "table") && !strings.Contains(route, "main") {
			matches := tableRegex.FindStringSubmatch(route)
			if len(matches) > 1 && matches[1] != "default" {
				tableName := matches[1]
				if _, err := strconv.Atoi(tableName); err == nil {
					flushCmd := exec.Command("ip", "route", "flush", "table", tableName)
					if err := flushCmd.Run(); err == nil {
						fmt.Println("Deleted routes in table", tableName)
					}
				}
			}
		}
	}
}

// deleteAllTun 删除所有以"tun_"开头的网络接口
func deleteAllTun() {
	// 使用awk命令处理`ip link show`的输出，排除lo, vir, wl开头的接口，以及不符合格式的行
	cmd := exec.Command("sh", "-c", "ip link show | awk -F: '$0 !~ \"lo|vir|wl|^[^0-9]\" {print $2; getline}'")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Failed to execute command:", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		interfaceName := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(interfaceName, "tun_") {
			delCmd := exec.Command("ip", "link", "delete", interfaceName)
			if err := delCmd.Run(); err == nil {
				fmt.Printf("Deleted interface: %s\n", interfaceName)
			} else {
				fmt.Printf("Failed to delete interface: %s\n", interfaceName)
			}
		}
	}
}

func setFirewallForwardAccept() {
	sections, ok := uci.GetSections("firewall", "defaults")
	if !ok {
		log.Print("no uci firewall defaults found")
		return
	}
	for _, section := range sections {
		ok := uci.Set("firewall", section, "forward", "ACCEPT")
		if !ok {
			log.Print("failed to set firewall forward accept")
		}
	}
	sections, ok = uci.GetSections("firewall", "zone")
	if !ok {
		log.Print("no uci firewall zone found")
		return
	}
	for _, section := range sections {
		ok := uci.Set("firewall", section, "forward", "ACCEPT")
		if !ok {
			log.Print("failed to set firewall forward accept")
		}
	}
	err := uci.Commit()
	if err != nil {
		log.Print("failed to commit uci")
	}
	execute("/etc/init.d/firewall reload")
}

func runTun2socks(id int, tunName string, localPort int) {
	cmd := exec.Command("/bin/ash", "-c", fmt.Sprintf("tun2socks -device %s --udp-timeout 2m -proxy socks5://127.0.0.1:%d", tunName, localPort))
	// 启动子进程
	if err := cmd.Start(); err != nil {
		fmt.Println("启动命令失败:", err)
		return
	}
	tun2socksMap[id] = cmd
}

func stopAllss() {
	ssMap.Range(func(key, value interface{}) bool {
		client := value.(*ss.Client)
		err := client.Stop()
		if err != nil {
			log.Printf("stop client: %v", err)
		}
		return true
	})
	if defaultSSCli != nil {
		err := defaultSSCli.Stop()
		if err != nil {
			log.Printf("stop default client: %v", err)
		}
	}
	ssMap = sync.Map{}
}

func stopAllTun2socks() {
	for id, cmd := range tun2socksMap {
		if err := cmd.Process.Kill(); err != nil {
			fmt.Printf("停止tun2socks失败: %s\n", err)
		} else {
			fmt.Printf("停止tun2socks成功: %d\n", id)
		}
	}
	clear(tun2socksMap)
}

func removeVersions() {
	uci.Del("transip", "@info[0]", "rule_version")
	uci.Del("transip", "@info[0]", "client_infos_md5")
	uci.Commit()
}

func domainAddrToIPAddress(domainAddr string) (string, error) {
	h, p, err := net.SplitHostPort(domainAddr)
	if err != nil {
		return "", err
	}
	if h == "" {
		return "", fmt.Errorf("no host found in domain %s", domainAddr)
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no ip found for domain %s", domainAddr)
	}
	ip := ips[rand.Intn(len(ips))].String()

	return fmt.Sprintf("%s:%s", ip, p), nil
}

func genConnecter(server *pb.ProxyServers) (ss.Connecter, ss.PcConnecter) {
	udpType, _ := getUciInfo("udp_type")
	serverAddr := fmt.Sprintf("%s:%d", server.Ip, server.Port)
	uotServerAddr := fmt.Sprintf("%s:%d", server.Ip, server.UotPort)
	tcpRawServerAddr := fmt.Sprintf("%s:%d", server.Ip, server.TcprawPort)
	tcpConnecter := &ss.TCPConnecter{
		ServerAddr: serverAddr,
	}
	var udpConnecter ss.PcConnecter
	udpConnecter = &ss.UDPConnecter{
		ServerAddress: serverAddr,
	}
	switch udpType {
	case "tcpraw":
		if server.TcprawPort == 0 {
			break
		}
		log.Printf("Tcpraw server addr: %s", tcpRawServerAddr)
		udpConnecter = &ss.TcpRawConnecter{
			ServerAddress: tcpRawServerAddr,
		}
	case "uot":
		if server.UotPort == 0 {
			break
		}
		log.Printf("use UOT connecter to %s", uotServerAddr)
		udpConnecter = &ss.UotConnecter{
			ServerAddress: uotServerAddr,
		}
	}

	return tcpConnecter, udpConnecter
}
