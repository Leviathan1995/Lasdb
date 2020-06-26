package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"github.com/leviathan1995/Trident/client/util"
)


func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".trident-client.json", "client config")
	flag.Parse()

	bytes, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("Reading %s failed.", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("Parsing %s failed.", conf)
	}

	var proxyIP, proxyURL []string
	url, _ := config["proxy_url"].([]interface{})

	for _, url := range url {
		proxyURL = append(proxyURL, url.(string))
	}

	for _, url := range proxyURL {
		ipAddr, _ := net.LookupIP(url)
		for _, ip := range ipAddr {
			proxyIP = append(proxyIP, ip.String())
		}
	}

	var serverAddrs []string
	serverAddr, _ := config["server_addr"].([]interface{})

	for _, addr := range serverAddr {
		serverAddrs = append(serverAddrs, addr.(string))
	}

	clientImpl := client.NewClient(serverAddrs, config["listen_addr"].(string), config["password"].(string), proxyIP)
	_ = clientImpl.Listen()
}
