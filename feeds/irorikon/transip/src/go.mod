module transip

go 1.22.1

require (
	github.com/digineo/go-uci v0.0.0-20210918132103-37c7b10c14fa
	github.com/geewan-rd/transip-connecter v0.0.2-0.20240414112458-3a0e93e97910
	github.com/shadowsocks/go-shadowsocks2 v0.1.5
	google.golang.org/grpc v1.62.1
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-iptables v0.7.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/redis/go-redis/v9 v9.5.1 // indirect
	github.com/xtaci/tcpraw v1.2.25 // indirect
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/geewan-rd/transip-relay-server v0.0.0-20240409153122-270d3788a30e
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/juju/ratelimit v1.0.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240123012728-ef4313101c80 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace github.com/shadowsocks/go-shadowsocks2 => github.com/geewan-rd/go-shadowsocks2 v1.3.0

replace github.com/geewan-rd/transip-relay-server => /home/fregie/software/transip-relay-server
