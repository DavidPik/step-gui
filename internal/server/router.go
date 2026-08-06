package server

import (
    "github.com/labstack/echo/v4"
    "step-gui/internal/config"
)

func RegisterRoutes(e *echo.Echo, cfg *config.Config) {
    api := e.Group("/api")

    // Health
    api.GET("/health", handlers.Health)

    // Authorities
    handlers.RegisterAuthorityHandlers(api)

    // Policies
    handlers.RegisterPolicyHandlers(api)

    // Provisioners
    handlers.RegisterProvisionerHandlers(api)

    // Certificates
    handlers.RegisterCertificateHandlers(api)

    // Users
    handlers.RegisterUserHandlers(api)

    // Audit
    handlers.RegisterAuditHandlers(api)

    // Health check
    api.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

}
