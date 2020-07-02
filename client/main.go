package main

import (
	"encoding/json"
	"flag"
	"github.com/leviathan1995/Trident/client/util"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	var conf string
	var config map[string]interface{}
	var enableBypass bool
	flag.StringVar(&conf, "c", ".trident-client.json", "The client configuration.")
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

	var srvAdders []string
	srvAddr, _ := config["server_addr"].([]interface{})

	for _, ip := range srvAddr {
		srvAdders = append(srvAdders, ip.(string))
	}

	Bypass := int(config["bypass"].(float64))

	if Bypass == 0 {
		enableBypass = false
	} else {
		enableBypass = true
	}

	c := client.NewClient(config["listen_addr"].(string), srvAdders, proxyIP, config["password"].(string), enableBypass)
	err = c.Listen()
	if err != nil {
		log.Printf("Listen failed. %s", err.Error())
	}
}
