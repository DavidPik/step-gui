package server

import (
    "github.com/labstack/echo/v4"
    "step-gui/internal/config"
)

func RegisterRoutes(e *echo.Echo, cfg *config.Config) {
    api := e.Group("/api")

    // Health check
    api.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

    // TODO: add handlers for authorities, policies, provisioners, certificates, users, audit
}
