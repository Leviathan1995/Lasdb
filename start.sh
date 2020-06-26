#!/bin/bash

if [ "$1" = "client" ]
then
  sudo mkdir -p /root/proxy/
  sudo cp trident-client.service /etc/systemd/system/
  sudo cp trident-client /root/proxy/
  sudo cp .trident-client.json /root/proxy/
  systemctl enable trident-client
  systemctl start trident-client
  systemctl status trident-client -l
elif [ "$1" = "server" ]
then
  sudo mkdir -p /root/proxy/
  sudo cp trident-server.service /etc/systemd/system/
  sudo cp trident-server /root/proxy/
  sudo cp .trident-server.json /root/proxy/
  systemctl enable trident-server
  systemctl start trident-server
  systemctl status trident-server -l
else
  echo "Invalid parameter"
fi
