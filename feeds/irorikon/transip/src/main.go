package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	pb "github.com/geewan-rd/transip-connecter/proto"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultModel          = "TransIP加速盒子"
	interval              = 5 * time.Second
	defaultMethd          = "aes-256-cfb"
	defaultUDPBufSize     = 64 * 1024
	localPortBase         = 10000
	redirPortBase         = 20000
	defaultProxyLocalPort = 11000
	defaultRdierPort      = 21000
)

var httpc = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func main() {
	socks.UDPEnabled = true
	setFirewallForwardAccept()
	resetNetwork()
	removeVersions()
	if len(os.Args) > 1 {
		return
	}
	go func() {
		for {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer cancel()
				ticker := time.NewTicker(5 * time.Second)
				originToken, err := getUciInfo("token")
				if err != nil {
					log.Printf("get token: %v", err)
				}
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						token, err := getUciInfo("token")
						if err != nil {
							log.Printf("get token: %v", err)
							return
						}
						if token != originToken {
							log.Printf("token changed, reconnecting")
							return
						}
					}
				}
			}()
			err := grpcLongConnection(ctx)
			if err != nil {
				log.Printf("connect grpc: %v", err)
			}
			log.Printf("Getting rules...")
			proxies, err := getRules()
			if err != nil {
				log.Printf("get rules: %v", err)
				goto SLEEP
			}
			log.Printf("Got rules")
			err = applyRule(proxies)
			if err != nil {
				log.Printf("apply rule: %v", err)
				goto SLEEP
			}
		SLEEP:
			cancel()
			time.Sleep(5 * time.Second)
		}
	}()

	ticker := time.NewTicker(interval)
	for range ticker.C {
		err := uploadMetadata()
		if err != nil {
			log.Printf("uploadMetadata: %v", err)
		}
	}
}

func grpcLongConnection(ctx context.Context) error {
	grpcAddr, err := getUciInfo("connecter_addr")
	if err != nil {
		return err
	}
	token, err := getUciInfo("token")
	if err != nil {
		return err
	}
	uuid, err := GetUUID()
	if err != nil {
		return err
	}
	log.Printf("uuid: %s", uuid)
	ipGrpcAddr, err := domainAddrToIPAddress(grpcAddr)
	if err != nil {
		return err
	}
	log.Printf("grpc addr: %s", ipGrpcAddr)
	tlsconfig := tls.Config{InsecureSkipVerify: true}
	cert, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		log.Fatalf("init abs failed, cert failed: %s", err)
	}
	tlsconfig.Certificates = []tls.Certificate{cert}
	cred := credentials.NewTLS(&tlsconfig)
	conn, err := grpc.Dial(ipGrpcAddr, grpc.WithTransportCredentials(cred))
	if err != nil {
		return fmt.Errorf("dial: %v", err)
	}
	cli := pb.NewConnecterClient(conn)
	stream, err := cli.Rule(ctx, &pb.RuleRequest{Token: token, Uuid: uuid})
	if err != nil {
		return fmt.Errorf("rule api: %v", err)
	}
	for {
		rule, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %v", err)
		}
		if rule.Code != 0 {
			return fmt.Errorf("error: %s", rule.Msg)
		}
		log.Printf("apply rule version: %s", rule.Md5)
		err = applyRule(rule.Proxies)
		if err != nil {
			return err
		}
		saveUci("rule_version", rule.Md5)
	}
}

type RspStatus struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

type metadataReq struct {
	Metadata Metadata `json:"metadata"`
	SrcIPs   []string `json:"src_ip"`
	SrcMacs  []string `json:"src_mac"`
	UUID     string   `json:"uuid"`
}

type Metadata struct {
	PublicIP string `json:"public_ip"`
	Model    string `json:"model"`
}

func uploadMetadata() error {
	token, err := getUciInfo("token")
	if err != nil {
		return err
	}
	baseUrl, err := getUciInfo("base_url")
	if err != nil {
		return err
	}
	if token == "" || baseUrl == "" {
		return fmt.Errorf("no token or base_url found")
	}
	uuid, err := GetUUID()
	if err != nil {
		return err
	}

	clientInfos, clientInfosMd5, err := getAllClientInfo()
	if err != nil {
		return err
	}
	oldMd5, _ := getUciInfo("client_infos_md5")
	if oldMd5 == clientInfosMd5 {
		// log.Printf("no change in client infos")
		return nil
	}
	body := metadataReq{
		Metadata: Metadata{
			Model: defaultModel,
		},
		SrcIPs:  make([]string, 0),
		SrcMacs: make([]string, 0),
		UUID:    uuid,
	}
	for _, info := range clientInfos {
		body.SrcIPs = append(body.SrcIPs, fmt.Sprintf("%s (%s)", info.IP, info.Name))
		body.SrcMacs = append(body.SrcMacs, fmt.Sprintf("%s (%s)", info.Mac, info.Name))
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	// log.Printf("upload metadata: %s", jsonBody)
	req, err := http.NewRequest("POST", baseUrl+"/v1/router/metadata", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	var rsp RspStatus
	err = json.NewDecoder(resp.Body).Decode(&rsp)
	if err != nil {
		return err
	}
	if rsp.Code != 0 {
		return fmt.Errorf("error: %s", rsp.Error)
	}
	log.Printf("upload metadata success.%d mac %d ip", len(body.SrcMacs), len(body.SrcIPs))
	err = saveUci("client_infos_md5", clientInfosMd5)
	if err != nil {
		return err
	}
	return nil
}

// type Proxies struct {
// 	ProxyNodes   []ProxyNodes   `json:"proxy_nodes"`
// 	ProxyRules   []ProxyRules   `json:"proxy_rules"`
// 	ProxyServers []ProxyServers `json:"proxy_servers"`
// 	RouterName   string         `json:"router_name"`
// }
// type ProxyNodes struct {
// 	Account    string `json:"account"`
// 	ExpireTime string `json:"expire_time"`
// 	Host       string `json:"host"`
// 	ID         int    `json:"id"`
// 	IP         string `json:"ip"`
// 	Password   string `json:"password"`
// 	Port       int    `json:"port"`
// 	Region     string `json:"region"`
// 	Remark     string `json:"remark"`
// }
// type ProxyRules struct {
// 	ProxyID int      `json:"proxy_id"`
// 	SrcIP   []string `json:"src_ip"`
// 	SrcMac  []string `json:"src_mac"`
// }
// type ProxyServers struct {
// 	ID       int    `json:"id"`
// 	IP       string `json:"ip"`
// 	Password string `json:"password"`
// 	Port     int    `json:"port"`
// 	Region   string `json:"region"`
// 	Remark   string `json:"remark"`
// }

// func ProxiesFromPB(pbProxies *pb.Proxies) *Proxies {
// 	proxies := &Proxies{
// 		ProxyNodes:   make([]ProxyNodes, 0),
// 		ProxyRules:   make([]ProxyRules, 0),
// 		ProxyServers: make([]ProxyServers, 0),
// 		RouterName:   pbProxies.RouterName,
// 	}
// 	for _, pbNode := range pbProxies.ProxyNodes {
// 		proxies.ProxyNodes = append(proxies.ProxyNodes, ProxyNodes{
// 			Account:  pbNode.Account,
// 			Host:     pbNode.Host,
// 			ID:       int(pbNode.Id),
// 			IP:       pbNode.Ip,
// 			Password: pbNode.Password,
// 			Port:     int(pbNode.Port),
// 			Region:   pbNode.Region,
// 			Remark:   pbNode.Remark,
// 		})
// 	}
// 	for _, pbRule := range pbProxies.ProxyRules {
// 		proxies.ProxyRules = append(proxies.ProxyRules, ProxyRules{
// 			ProxyID: int(pbRule.ProxyId),
// 			SrcIP:   pbRule.SrcIp,
// 			SrcMac:  pbRule.SrcMac,
// 		})
// 	}
// 	for _, pbServer := range pbProxies.ProxyServers {
// 		proxies.ProxyServers = append(proxies.ProxyServers, ProxyServers{
// 			ID:       int(pbServer.Id),
// 			IP:       pbServer.Ip,
// 			Password: pbServer.Password,
// 			Port:     int(pbServer.Port),
// 			Region:   pbServer.Region,
// 			Remark:   pbServer.Remark,
// 		})
// 	}
// 	return proxies
// }

type getRuleRsp struct {
	RspStatus
	Proxy pb.Proxies `json:"proxies"`
	Md5   string     `json:"md5"`
}

func getRules() (*pb.Proxies, error) {
	token, err := getUciInfo("token")
	if err != nil {
		return nil, err
	}
	baseUrl, err := getUciInfo("base_url")
	if err != nil {
		return nil, err
	}
	if token == "" || baseUrl == "" {
		return nil, fmt.Errorf("no token or base_url found")
	}
	uuid, err := GetUUID()
	if err != nil {
		return nil, err
	}
	ruleVersion, _ := getUciInfo("rule_version")
	url := fmt.Sprintf("%s/v1/router/proxy-rules?uuid=%s", baseUrl, uuid)
	if ruleVersion != "" {
		url += "&md5=" + ruleVersion
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotModified {
			return nil, fmt.Errorf("not modified")
		}
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}
	var rsp getRuleRsp
	err = json.NewDecoder(resp.Body).Decode(&rsp)
	if err != nil {
		return nil, err
	}
	if rsp.Code != 0 {
		return nil, fmt.Errorf("error: %s", rsp.Error)
	}
	err = saveUci("rule_version", rsp.Md5)
	if err != nil {
		return nil, err
	}
	return &rsp.Proxy, nil
}
