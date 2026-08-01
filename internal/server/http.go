package server

import (
    "github.com/labstack/echo/v4"
    "step-gui/internal/config"
)

func Start(cfg *config.Config) {
    e := echo.New()
    RegisterRoutes(e, cfg)
    e.Logger.Fatal(e.Start(":8443"))
}
