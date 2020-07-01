# Trident

### 生成证书

Ｓerver:
```
 openssl req -new -x509 -key server.key -out server.pem -days 3650
```

Client:
```
openssl req -new -x509 -key client.key -out client.pem -days 3650
```
