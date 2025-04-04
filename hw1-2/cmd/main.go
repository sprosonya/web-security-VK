package main

import (
	"log"
	"proxy/cfg"
	"proxy/internal/server"
)

func main() {
	var p server.ProxyServer
	config, err := cfg.GetConfig("./cfg/config.yaml")
	if err != nil {
		log.Fatalf("Could not load configuration: %v", err)
	}
	err = p.Start(config)
	if err != nil {
		log.Fatalf("Could not start proxy: %v", err)
	}
}
