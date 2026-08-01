package main

import (
    "step-gui/internal/config"
    "step-gui/internal/server"
)

func main() {
    cfg := config.Load()
    server.Start(cfg)
}
