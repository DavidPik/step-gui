package server

import (
    "fmt"
    "github.com/labstack/echo/v4"
    "step-gui/internal/config"
)

func Start(cfg *config.Config) {
    e := echo.New()

    RegisterRoutes(e, cfg)

    addr := fmt.Sprintf(":%d", cfg.Server.Port)
    e.Logger.Infof("Starting step-gui backend on %s", addr)

    e.Logger.Fatal(e.Start(addr))
}
