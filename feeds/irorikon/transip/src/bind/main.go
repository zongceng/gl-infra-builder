package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/digineo/go-uci"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <token>\n", os.Args[0])
		os.Exit(1)
	}
	token := os.Args[1]
	if token == "" {
		fmt.Println("Token is empty")
		os.Exit(1)
	}
	fmt.Printf("Token: %s\n", token)
	baseUrl, err := getUciInfo("base_url")
	if err != nil {
		log.Printf("get base_url failed: %v", err)
		return
	}
	if token == "" || baseUrl == "" {
		log.Printf("token or base_url is empty")
		return
	}
	uuid, err := GetUUID()
	if err != nil {
		log.Printf("get uuid failed: %v", err)
		return
	}
	log.Printf("UUID: %s", uuid)
	body := map[string]string{
		"token": token,
		"uuid":  uuid,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		log.Printf("marshal json failed: %v", err)
		return
	}
	req, err := http.NewRequest("POST", baseUrl+"/v1/router/token-bind", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("create request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("do request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("response status: %s", resp.Status)
	var rsp RspStatus
	err = json.NewDecoder(resp.Body).Decode(&rsp)
	if err != nil {
		log.Printf("decode response failed: %v", err)
		return
	}
	if rsp.Code != 0 {
		log.Printf("response code: %d, error: %s", rsp.Code, rsp.Error)
		return
	}
	saveUci("token", token)
	log.Printf("bind token success")
}

type RspStatus struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

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
