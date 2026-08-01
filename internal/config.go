package config

import (
    "gopkg.in/yaml.v3"
    "os"
)

type Config struct {
    Database struct {
        Host     string `yaml:"host"`
        Port     int    `yaml:"port"`
        User     string `yaml:"user"`
        Password string `yaml:"password"`
        Name     string `yaml:"name"`
    } `yaml:"database"`

    StepCA struct {
        URL         string `yaml:"url"`
        Provisioner string `yaml:"provisioner"`
        KeyFile     string `yaml:"key_file"`
    } `yaml:"step_ca"`
}

func Load() *Config {
    data, _ := os.ReadFile("config/config.yaml")
    var cfg Config
    yaml.Unmarshal(data, &cfg)
    return &cfg
}
