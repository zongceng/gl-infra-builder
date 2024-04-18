**Important**
关闭/etc/config/firewall中的转发

```bash
iptables -t nat -I POSTROUTING -p all -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j MASQUERADE
iptables -t nat -I POSTROUTING -p all -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE

国内入口: 218.205.94.154
出口: 128.14.97.35

http://101.132.242.13/server_conf.json

curl -X 'POST' \
  'https://test.tikvpn.in/v1/admin/router/generate_token' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTg3ODAyNzQsImlhdCI6MTcxMTAwNDI3NCwia2V5IjoiMUMzNUNBRDFBODE2RTAwMEFdMlIxNXdzNnYxQTAzNFA4dDJ2eFlVWThmN280N2t2MTkyVjhzNTM3X0VaaTF2MSIsInVpZCI6Mn0.ZprHO-ec5hcnlxCMhUmuf4HQPJWlPZ8hhPdQg1N3NAI' \
  -H 'Content-Type: application/json' \
  -d '{
  "user_id": "2"
}'


curl -X 'POST' \
  'https://test.tikvpn.in/v1/user_ctl/user/login' \
  -H 'Content-Type: application/json' \
  -d '{
  "account": "helinhan2",
  "password": "123456"
 }'

curl -X 'POST' \
  'https://test.tikvpn.in/v1/router/token-bind' \
  -H 'Content-Type: application/json' \
  -d '{
  "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NzAwMTE0NzQsImlhdCI6MTcxMjMzMTQ3NCwia2V5IjoiMUM0OTkxQUVCNzVCRDAwMG5IcWEwWXBZNzU0Zm9qcHVETUUxdXRnW2cwMzNqOTlwRGJEUzVvUFxcTzd1NUNmenkiLCJ1aWQiOjIzfQ.q-Qt3gq97hvNVgAMmP8cRFUSvptad3BJspxa-6k0CbA",
  "uuid": "KHxPhnEr"
}'

curl -X 'POST' \
  'https://api.elreach.com/v1/router/token-bind' -v \
  -H 'Content-Type: application/json' \
  -d '{
  "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NzAxNTkyMzAsImlhdCI6MTcxMjQ3OTIzMCwia2V5IjoiMUM0QkM1NTQ1RDQxRDAwMFpfcmlrcDdoYTZbZTExOTN3cTBJMHBvQ0IxMzZ0eTg2ODhzNWMxNTMwZjBtOHp4NyIsInVpZCI6MTAwMDAwfQ.8DextGNQjYJaZPYMHZwAfV7DA9Vo8pICub-aheqGElg",
  "uuid": "fc:83:c6:0e:f2:e4"
}'

curl -X 'GET' \
  'https://test.tikvpn.in/v1/user_ctl/router?user_id=2' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTg3ODAyNzQsImlhdCI6MTcxMTAwNDI3NCwia2V5IjoiMUMzNUNBRDFBODE2RTAwMEFdMlIxNXdzNnYxQTAzNFA4dDJ2eFlVWThmN280N2t2MTkyVjhzNTM3X0VaaTF2MSIsInVpZCI6Mn0.ZprHO-ec5hcnlxCMhUmuf4HQPJWlPZ8hhPdQg1N3NAI'

curl -X 'DELETE' \
  'https://test.tikvpn.in/v1/admin/router/13' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTg3ODAyNzQsImlhdCI6MTcxMTAwNDI3NCwia2V5IjoiMUMzNUNBRDFBODE2RTAwMEFdMlIxNXdzNnYxQTAzNFA4dDJ2eFlVWThmN280N2t2MTkyVjhzNTM3X0VaaTF2MSIsInVpZCI6Mn0.ZprHO-ec5hcnlxCMhUmuf4HQPJWlPZ8hhPdQg1N3NAI'

curl -X 'GET' \
  'https://test.tikvpn.in/v1/router/proxy-rules?uuid=f8:5e:3c:5b:18:a0' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NzA2OTg3MDIsImlhdCI6MTcxMzAxODcwMiwia2V5IjoiMUM1M0NGNDBDMEREMTAwMDBoUDE4bFc0eDVCM1NMXFx1Z0w5RW5hN0I4SXNeOXo1ODFibUswXVk4VXI1QWlsXlEiLCJ1aWQiOjIzfQ.6GywaN8Q7Z7lsaxKSs5Tgdyzxbx2p_xDfvD-FNQWlYo'

curl -X 'GET' \
  'https://api.elreach.com/v1/router/proxy-rules?uuid=fc:83:c6:0e:f2:e4' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NzAwODU3MjIsImlhdCI6MTcxMjQwNTcyMiwia2V5IjoiMUM0QUFDRUFGNDgxQzAwMFgxb2hpOVxcazRqWHY2eG9qcDE2MzFHRERYajNuMzg2XzY5N143NXdFMzdtN3ZRdmIiLCJ1aWQiOjEwMDAwMH0.cCFbCdYVBKmsZK3M8avyqegdPBOVGJH_Y1LDcdPQEkw'

uci set transip.@info[0].udp_type='uot'
uci commit transip
/etc/init.d/transip restart
```