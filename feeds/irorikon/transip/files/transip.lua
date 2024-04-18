local json = require 'dkjson'
local os = require 'os'
local uci = require('uci').cursor()

function main()
  os.execute("killall trojan-go")
  os.execute("killall tun2socks")
  os.execute("mkdir -p /etc/transip/trojan_conf")

  local lan_cidr = get_lan_cidr()
  os.execute("iptables -t mangle -N TROJAN_MARK")
  os.execute("iptables -t mangle -F TROJAN_MARK")
  os.execute("iptables -t mangle -D PREROUTING -j TROJAN_MARK")
  os.execute(string.format("iptables -t nat -D POSTROUTING -p all -s %s ! -d %s -j MASQUERADE", lan_cidr, lan_cidr))
  os.execute("iptables -t nat -D POSTROUTING -p all -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE")
  
  delete_custom_ip_routes()
  delete_custom_ip_rules()
  delete_all_tun()
  
  if arg[1] == "stop" or arg[2] == "stop" then
    return
  end

  set_firewll_forward_accept()

  os.execute("iptables -t mangle -A PREROUTING -j TROJAN_MARK")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 0/8 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 127/8 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 10/8 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 169.254/16 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 172.16/12 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 192.168/16 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 224/4 -j RETURN")
  os.execute("iptables -t mangle -A TROJAN_MARK -d 240/4 -j RETURN")
  os.execute(string.format("iptables -t nat -I POSTROUTING -p all -s %s ! -d %s -j MASQUERADE", lan_cidr, lan_cidr))
  os.execute("iptables -t nat -I POSTROUTING -p all -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE")


  local serverFilePath = arg[1]
  local serverf = io.open(serverFilePath, "r")

  if not serverf then
    print("Cannot open file: " .. serverFilePath)
    os.exit()
  end
  
  local fileContent = serverf:read("*all")
  serverf:close()
  
  local conf, pos, err = json.decode(fileContent, 1, nil)
  if err then
    print("Error:", err)
    os.exit()
  end

  local rules = {}
  uci:foreach("transip", "rule", function(s)
    local rule = {}
    rule.client_mac = {}
    if type(s.client_mac) == "table" then
      for i, v in ipairs(s.client_mac) do
        table.insert(rule.client_mac, v)
      end
    else
      table.insert(rule.client_mac, s.client_mac)
    end

    rule.client_ip = {}
    if type(s.client_ip) == "table" then
      for i, v in ipairs(s.client_ip) do
        table.insert(rule.client_ip, v)
      end
    else
      table.insert(rule.client_ip, s.client_ip)
    end

    rule.proxy_id = tonumber(s.server)

    -- 将当前 rule 对象添加到数组中
    table.insert(rules, rule)
end)


  -- 启动所有必要的trojan和tun2socks客户端
  local proxy_ids = {}
  local id_tun_map = {}

  for i, v in ipairs(rules) do
    if proxy_ids[v.proxy_id] == nil then
      local proxy
      local proxy_no
      for j, p in ipairs(conf.all_proxies) do
        if p.id == v.proxy_id then
          proxy = p
          proxy_no = j
          break
        end
      end
      if proxy == nil then
        print("Cannot find proxy with id: " .. v.proxy_id)
        os.exit()
      end
      -- 生成trojan配置文件
      local local_port = 1080 + proxy_no
      local trojan_conf = {
        run_type = "client",
        local_addr = "127.0.0.1",
        local_port = local_port,
        remote_addr = proxy.remote_addr,
        remote_port = proxy.remote_port,
        password = proxy.password,
        ssl = proxy.ssl
      }
      local trojanConfFilePath = string.format("/etc/transip/trojan_conf/%d.json", v.proxy_id)
      local trojanConfFile = io.open(trojanConfFilePath, "w")
      if not trojanConfFile then
        print("Cannot open file: " .. trojanConfFilePath)
        os.exit()
      end
      local trojanConfJson = json.encode(trojan_conf, { indent = true })
      trojanConfFile:write(trojanConfJson)
      trojanConfFile:close()
      -- 启动trojan-go
      local trojanGoCmd = string.format("nohup trojan-go -config %s &", trojanConfFilePath)
      os.execute(trojanGoCmd)

      -- 启动tun2socks
      local tun_name = string.format("tun_%d", proxy_no)
      os.execute(string.format("ip tuntap add mode tun dev %s", tun_name))
      os.execute(string.format("ip addr add 10.0.0.%d/24 dev %s", proxy_no, tun_name))
      os.execute(string.format("ip link set %s up", tun_name))
      local tun2socksCmd = string.format("nohup tun2socks -device %s -proxy socks5://127.0.0.1:%d &", tun_name, local_port)
      os.execute(tun2socksCmd)

      id_tun_map[v.proxy_id] = tun_name
      proxy_ids[v.proxy_id] = true
    end
  end

  -- 配置策略路由
  for proxy_id, tun_name in pairs(id_tun_map) do
    os.execute(string.format("ip route add 0.0.0.0/0 dev %s table %d", tun_name, proxy_id))
    os.execute(string.format("ip rule add fwmark %d table %d", proxy_id, proxy_id))
  end

  -- 客户端标记
  for i, v in ipairs(rules) do
    for j, mac in ipairs(v.client_mac) do
      print(mac)
      os.execute(string.format("iptables -t mangle -A TROJAN_MARK -m mac --mac-source %s -j MARK --set-mark %d", mac, v.proxy_id))
    end
    for j, ip in ipairs(v.client_ip) do
      os.execute(string.format("iptables -t mangle -A TROJAN_MARK -s %s -j MARK --set-mark %d", ip, v.proxy_id))
    end
  end
end

function delete_all_tun()
  -- 导入os库
  local os = require("os")

  -- 执行shell命令，获取所有接口的名称
  local handle = io.popen("ip link show | awk -F: '$0 !~ \"lo|vir|wl|^[^0-9]\" {print $2;getline}'")
  local result = handle:read("*a")
  handle:close()

  -- 检查每个接口的名称
  for interface in result:gmatch("%S+") do
      -- 如果接口的名称以"tun_"开头，就删除它
      if interface:find("^tun_") then
          os.execute("ip link delete " .. interface)
      end
  end
end

-- 执行系统命令并获取输出
function exec_command(command)
  local handle = io.popen(command)
  local result = handle:read("*a")
  handle:close()
  return result
end

-- 删除非默认的 IP 规则
function delete_custom_ip_rules()
  local rules = exec_command("ip rule")
  for rule in rules:gmatch("[^\r\n]+") do
      if not rule:find("lookup main") and not rule:find("lookup default") and not rule:find("lookup local") then
          local rule_priority = rule:match("(%d+):")
          if rule_priority then
              os.execute("ip rule del prio " .. rule_priority)
              print("Deleted rule with priority " .. rule_priority)
          end
      end
  end
end

-- 删除非默认的 IP 路由
function delete_custom_ip_routes()
  local routes = exec_command("ip route show table all")
  for route in routes:gmatch("[^\r\n]+") do
      if route:find("table") and not route:find("main") then
          -- 这里假设非默认的路由会包含 "table" 但不是 "main"
          local table_name = route:match("table (%S+)")
          if table_name and tonumber(table_name) then -- 排除默认表，假设它们是数字编号
              os.execute("ip route flush table " .. table_name)
              print("Delete routes in table " .. table_name)
          end
      end
  end
end

function maskToCIDR(netmask)
  local cidr = 0
  for octet in netmask:gmatch("%d+") do
      octet = tonumber(octet)
      while octet > 0 do
          cidr = cidr + (octet % 2)
          octet = math.floor(octet / 2)
      end
  end
  return cidr
end

function get_lan_cidr()
  local uci = require('uci').cursor()
  local ipaddr = uci:get("network", "lan", "ipaddr")
  local netmask = uci:get("network", "lan", "netmask")
  local cidr = maskToCIDR(netmask)
  return ipaddr .. "/" .. cidr
end

function set_firewll_forward_accept()
  uci:foreach("firewall", "defaults", function(s)
    uci:set("firewall", s[".name"], "forward", "ACCEPT")
  end)
  uci:foreach("firewall", "zone", function(s)
    if s.name == "lan" then
      uci:set("firewall", s.name, "forward", "ACCEPT")
    end
  end)
  uci:commit("firewall")
  os.execute("/etc/init.d/firewall reload")
end

main()
