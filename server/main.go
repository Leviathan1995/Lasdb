package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"

	"github.com/leviathan1995/Trident/server/util"
)

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".trident-server.json", "server config")
	flag.Parse()

	bytes, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("read %s failed.", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("parse %s failed.", conf)
	}

	enableTLS := int(config["tls"].(float64))
	tlsPort := int(config["tls_port"].(float64))

	s := server.NewServer(config["listen_addr"].(string), config["password"].(string), tlsPort)

	if enableTLS == 1 {
		go s.ListenTLS()
	}

	s.Listen()
}
