package cfg

import (
	"gopkg.in/yaml.v2"
	"log"
	"os"
)

type Config struct {
	ProxyServer struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
	Postgres struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		Username string `yaml:"user"`
		Password string `yaml:"password"`
		Database string `yaml:"dbname"`
	} `yaml:"db"`
	APIServer struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"apiserver"`
}

func GetConfig(path string) (*Config, error) {
	config := new(Config)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	if err = d.Decode(config); err != nil {
		return nil, err
	}
	log.Println("loaded config")
	return config, nil
}
