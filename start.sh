#!/bin/bash

if [ "$1" = "client" ]
then
  sudo mkdir -p /root/proxy/
  sudo cp trident-client.service /etc/systemd/system/
  sudo cp trident-client /usr/local/bin/
  sudo cp .trident-client.json /root/proxy/
  systemctl enable trident-client
  systemctl start trident-client
  systemctl status trident-client -l
elif [ "$1" = "server" ]
then
  sudo mkdir -p /root/proxy
  openssl genrsa -out server.key 2048
  openssl req -new -x509 -key server.key -out server.pem -days 3650
  openssl genrsa -out client.key 2048
  openssl req -new -x509 -key client.key -out client.pem -days 3650
  openssl pkcs12 -export -clcerts -in client.pem -inkey client.key -out root.p12 -passout pass:trident
  mv server.key server.pem client.key client.pem /etc/

  sudo cp trident-server.service /etc/systemd/system/
  sudo cp trident-server /usr/local/bin/
  sudo cp .trident-server.json /root/proxy/
  systemctl enable trident-server
  systemctl start trident-server
  systemctl status trident-server -l
else
  echo "Invalid parameter"
fi
