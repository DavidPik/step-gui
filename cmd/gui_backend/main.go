package main

import (
    "log"
    "step-gui/internal/config"
    "step-gui/internal/server"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
            log.Fatalf("failed to load config: %v", err)
    }
    
    server.Start(cfg)
}
