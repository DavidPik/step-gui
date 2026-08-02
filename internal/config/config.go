package config

import (
    "fmt"
    "gopkg.in/yaml.v3"
    "os"
)

type Config struct {
    Server struct {
        Port int `yaml:"port"`
    } `yaml:"server"`

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

func Load() (*Config, error) {
    data, err := os.ReadFile("config/config.yaml")
    if err != nil {
        return nil, fmt.Errorf("cannot read config.yaml: %w", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("cannot parse config.yaml: %w", err)
    }

    return &cfg, nil
}
