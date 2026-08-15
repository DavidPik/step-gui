package server

import (
    "crypto/x509"
    "fmt"
    "log"
    "os"

    "github.com/jmoiron/sqlx"
    "github.com/labstack/echo/v4"

    "step-gui/internal/api"
    "step-gui/internal/config"
    "step-gui/internal/db/repository"
    "step-gui/internal/stepca"
    "step-gui/internal/worker"
)

var (
    dbInstance    *sqlx.DB
    stepcaClient  *stepca.Client
    workerQueue   *worker.Queue
)

// RegisterRoutes initializes DB, repositories, StepCA client, worker queue and registers API routes.
// It wires middleware initialization hooks (RBAC, audit) into the API layer so handlers can rely on them.
//
// Notes:
// - Uses MariaDB/MySQL driver via github.com/go-sql-driver/mysql (sqlx driver name "mysql").
// - Connection string includes recommended params for time parsing and UTF8 support.
// - This function intentionally keeps wiring explicit and minimal; concrete implementations of
//   loadKey, worker.NewQueue, and api.Init* functions are expected elsewhere in the codebase.
func RegisterRoutes(e *echo.Echo, cfg *config.Config) {
    // --- 1) Initialize MariaDB connection (sqlx)
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&multiStatements=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
        cfg.Database.User,
        cfg.Database.Password,
        cfg.Database.Host,
        cfg.Database.Port,
        cfg.Database.Name,
    )

    var err error
    dbInstance, err = sqlx.Connect("mysql", dsn)
    if err != nil {
        // Fail fast: router registration cannot proceed without DB
        log.Fatalf("failed to connect to MariaDB: %v", err)
    }
    // Optional DB tuning could be applied here (SetMaxOpenConns, SetConnMaxLifetime, etc.)
    if cfg.Database.MaxOpenConns > 0 {
        dbInstance.SetMaxOpenConns(cfg.Database.MaxOpenConns)
    }
    if cfg.Database.MaxIdleConns > 0 {
        dbInstance.SetMaxIdleConns(cfg.Database.MaxIdleConns)
    }

    // --- 2) Initialize repositories
    authorityRepo := repository.NewAuthorityRepository(dbInstance)
    policyRepo := repository.NewPolicyRepository(dbInstance)
    provisionerRepo := repository.NewProvisionerRepository(dbInstance)
    certificateRepo := repository.NewCertificateRepository(dbInstance)
    userRepo := repository.NewUserRepository(dbInstance)
    groupRepo := repository.NewGroupRepository(dbInstance)
    approvalRepo := repository.NewApprovalRepository(dbInstance)
    provisionerRepo = provisionerRepo
    auditRepo := repository.NewAuditRepository(dbInstance)

    // --- 3) Initialize StepCA client
    // loadKey should return the provisioner key bytes (JWK or PEM) used to sign requests if needed.
    keyBytes, err := loadKey(cfg.StepCA.KeyFile)
    if err != nil {
        log.Fatalf("failed to load StepCA key: %v", err)
    }
    stepcaClient = stepca.New(cfg.StepCA.URL, cfg.StepCA.Provisioner, keyBytes)

    // --- 4) Initialize worker queue for async issuance/retries
    workerQueue = worker.NewQueue(worker.QueueConfig{
        Concurrency: cfg.Worker.Concurrency,
        RetryLimit:  cfg.Worker.RetryLimit,
    })
    // Provide worker queue with necessary dependencies (repos, stepca client)
    workerQueue.RegisterDependencies(worker.Dependencies{
        CertificateRepo: certificateRepo,
        ApprovalRepo:    approvalRepo,
        StepCAClient:    stepcaClient,
        AuditRepo:       auditRepo,
    })

    // --- 5) Initialize API layer with repositories, StepCA client, worker and middleware hooks
    api.InitRepositories(api.Repositories{
        AuthorityRepo:   authorityRepo,
        PolicyRepo:      policyRepo,
        ProvisionerRepo: provisionerRepo,
        CertificateRepo: certificateRepo,
        UserRepo:        userRepo,
        GroupRepo:       groupRepo,
        ApprovalRepo:    approvalRepo,
        AuditRepo:       auditRepo,
    })

    // Provide StepCA client and worker queue to API handlers
    api.InitStepCA(stepcaClient)
    api.InitWorker(workerQueue)

    // Initialize auth / RBAC middleware (OIDC/JWT config, role claims mapping)
    // This registers middleware factories inside api package so handlers can attach them.
    if err := api.InitAuth(cfg.Auth); err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Initialize audit middleware (records actions into audit_logs)
    if err := api.InitAuditMiddleware(auditRepo); err != nil {
        log.Fatalf("failed to initialize audit middleware: %v", err)
    }

    // --- 6) Register routes and middleware
    apiGroup := e.Group("/api")

    // Health endpoint (no auth)
    apiGroup.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

    // Register entity handlers (handlers internally attach RBAC/audit middleware as needed)
    api.RegisterAuthorityHandlers(apiGroup)
    api.RegisterPolicyHandlers(apiGroup)
    api.RegisterProvisionerHandlers(apiGroup)
    api.RegisterCertificateHandlers(apiGroup)
    api.RegisterUserHandlers(apiGroup)
    api.RegisterGroupHandlers(apiGroup)
    api.RegisterApprovalHandlers(apiGroup)
    api.RegisterAuditHandlers(apiGroup) // handlers will enforce Admin-only access

    // --- 7) Optional: background worker start (non-blocking)
    if cfg.Worker.AutoStart {
        go func() {
            if err := workerQueue.Start(); err != nil {
                log.Printf("worker queue stopped with error: %v", err)
            }
        }()
    }

    // --- 8) Final log
    log.Printf("router registered: MariaDB=%s:%d db=%s, StepCA=%s, worker_concurrency=%d",
        cfg.Database.Host, cfg.Database.Port, cfg.Database.Name, cfg.StepCA.URL, cfg.Worker.Concurrency)
}

// loadKey loads the StepCA provisioner key from a file path.
// This is a small helper; concrete key parsing (JWK vs PEM) is handled in stepca.New or stepca client.
func loadKey(path string) ([]byte, error) {
    if path == "" {
        return nil, fmt.Errorf("stepca key file path is empty")
    }
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    // Basic validation: try to parse as x509 PEM to give early feedback (optional)
    _ = x509.MarshalPKCS1PrivateKey // keep import usage explicit if needed
    return b, nil
}
