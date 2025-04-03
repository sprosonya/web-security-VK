package main

import (
	"log"
	"proxy/cfg"
	"proxy/internal/server"
)

func main() {
	config, err := cfg.GetConfig("./cfg/config.yaml")
	if err != nil {
		log.Printf("could not load configuration: %v", err)
	}
	var proxy server.ProxyServer
	if err := proxy.Start(config); err != nil {
		log.Fatal(err)
	}
}
