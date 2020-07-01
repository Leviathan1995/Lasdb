# Trident

### 生成证书

Server:
```
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.pem -days 3650
```

Client:
```
openssl genrsa -out client.key 2048
openssl req -new -x509 -key client.key -out client.pem -days 3650
```

pkcs12:
```
openssl pkcs12 -export -clcerts -in client.pem -inkey client.key -out root.p12 -passout pass:abc
```
