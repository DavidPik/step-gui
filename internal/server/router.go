package server

import (
    "github.com/jmoiron/sqlx"
    "github.com/labstack/echo/v4"
    "step-gui/internal/api"
    "step-gui/internal/config"
    "step-gui/internal/db/repository"
)

var dbInstance *sqlx.DB // inicializace bude později

func RegisterRoutes(e *echo.Echo, cfg *config.Config) {
    apiGroup := e.Group("/api")

    // init repositories
    authorityRepo := repository.NewAuthorityRepository(dbInstance)
    api.InitRepositories(authorityRepo)

    // health
    apiGroup.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

    // authorities
    api.RegisterAuthorityHandlers(apiGroup)

    // TODO: policies, provisioners, certificates, users, audit
}

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
