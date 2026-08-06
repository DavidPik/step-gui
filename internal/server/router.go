package server

import (
    "fmt"

    "github.com/jmoiron/sqlx"
    "github.com/labstack/echo/v4"

    "step-gui/internal/api"
    "step-gui/internal/config"
    "step-gui/internal/db/repository"
)

var dbInstance *sqlx.DB

func RegisterRoutes(e *echo.Echo, cfg *config.Config) {
    // DB připojení (zatím placeholder, skutečná inicializace bude v FÁZI 5)
    dbInstance = sqlx.MustConnect("mysql",
        fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
            cfg.Database.User,
            cfg.Database.Password,
            cfg.Database.Host,
            cfg.Database.Port,
            cfg.Database.Name,
        ),
    )

    // Inicializace repository instancí
    authorityRepo := repository.NewAuthorityRepository(dbInstance)
    policyRepo := repository.NewPolicyRepository(dbInstance)
    provisionerRepo := repository.NewProvisionerRepository(dbInstance)
    certificateRepo := repository.NewCertificateRepository(dbInstance)
    userRepo := repository.NewUserRepository(dbInstance)
    auditRepo := repository.NewAuditRepository(dbInstance)

    // Předání repository do API handlerů
    api.InitRepositories(
        authorityRepo,
        policyRepo,
        provisionerRepo,
        certificateRepo,
        userRepo,
        auditRepo,
    )

    // API group
    apiGroup := e.Group("/api")

    // Health endpoint
    apiGroup.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

    // Registrace všech API endpointů
    api.RegisterAuthorityHandlers(apiGroup)
    api.RegisterPolicyHandlers(apiGroup)
    api.RegisterProvisionerHandlers(apiGroup)
    api.RegisterCertificateHandlers(apiGroup)
    api.RegisterUserHandlers(apiGroup)
    api.RegisterAuditHandlers(apiGroup)

    stepcaClient = stepca.New(
        cfg.StepCA.URL,
        cfg.StepCA.Provisioner,
        loadKey(cfg.StepCA.KeyFile),
    )

}
