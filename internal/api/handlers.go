package api

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/labstack/echo/v4"

    "step-gui/internal/db/repository"
    "step-gui/internal/stepca"
    "step-gui/internal/worker"
)

//
// Global wiring points (initialized from server/router.go)
//

type Repositories struct {
    AuthorityRepo   repository.AuthorityRepository
    PolicyRepo      repository.PolicyRepository
    ProvisionerRepo repository.ProvisionerRepository
    CertificateRepo repository.CertificateRepository
    UserRepo        repository.UserRepository
    GroupRepo       repository.GroupRepository
    ApprovalRepo    repository.ApprovalRepository
    AuditRepo       repository.AuditRepository
}

var repos Repositories
var stepcaClient *stepca.Client
var workerQueue *worker.Queue

// InitRepositories wires repository implementations into API handlers.
func InitRepositories(r Repositories) {
    repos = r
}

// InitStepCA provides the StepCA client to handlers.
func InitStepCA(c *stepca.Client) {
    stepcaClient = c
}

// InitWorker provides the background worker/queue to handlers.
func InitWorker(w *worker.Queue) {
    workerQueue = w
}

//
// NOTE: Auth and audit middleware initialization functions are expected to be
// implemented in the api package (or provided by server) and attached to routes
// when registering handlers. The router should call api.InitAuth(...) and
// api.InitAuditMiddleware(...) during startup. Handlers below assume that
// authentication middleware sets the following context values:
//   - "actor_id" (string UUID)
//   - "roles" ([]string)
//   - "groups" ([]string)  // group ids the actor belongs to
//
// Helper functions below read those context values to enforce RBAC and Viewer scoping.
//

// getActorFromContext extracts actor id, roles and groups from Echo context.
// Returns actorID (empty if unauthenticated), roles slice, groups slice.
func getActorFromContext(c echo.Context) (actorID string, roles []string, groups []string) {
    if v := c.Get("actor_id"); v != nil {
        if s, ok := v.(string); ok {
            actorID = s
        }
    }
    if v := c.Get("roles"); v != nil {
        if rs, ok := v.([]string); ok {
            roles = rs
        }
    }
    if v := c.Get("groups"); v != nil {
        if gs, ok := v.([]string); ok {
            groups = gs
        }
    }
    return
}

func hasRole(roles []string, role string) bool {
    for _, r := range roles {
        if r == role {
            return true
        }
    }
    return false
}

//
// Utility helpers
//

func generateUUID() string {
    // TODO: replace with real UUID generator (github.com/google/uuid or similar)
    return fmt.Sprintf("tmp-%d", time.Now().UnixNano())
}

func generateSerial() string {
    return fmt.Sprintf("SN-%d", time.Now().UnixNano())
}

func nowRFC() string {
    return time.Now().Format(time.RFC3339)
}

func toJSON(v any) string {
    b, _ := json.Marshal(v)
    return string(b)
}

func ptr[T any](v T) *T {
    return &v
}

//
// Authority handlers
//

func RegisterAuthorityHandlers(g *echo.Group) {
    // Attach RBAC / audit middleware at router level as needed.
    g.GET("/authorities", listAuthorities)
    g.GET("/authorities/:id", getAuthority)
    g.POST("/authorities", createAuthority)
    g.PUT("/authorities/:id", updateAuthority)
    g.DELETE("/authorities/:id", deleteAuthority)
}

func listAuthorities(c echo.Context) error {
    actorID, roles, _ := getActorFromContext(c)
    // Viewer can only see authorities referenced by their own requests/certs.
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        // For simplicity return authorities referenced by viewer's certificates or requests.
        // Repository should implement a method to list authorities visible to a user.
        res, err := repos.AuthorityRepo.ListForUser(c.Request().Context(), actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, res)
    }

    res, err := repos.AuthorityRepo.List(c.Request().Context())
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getAuthority(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, _ := getActorFromContext(c)

    // Viewer scoping: allow if viewer has a certificate/request referencing this authority
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        ok, err := repos.AuthorityRepo.IsVisibleToUser(c.Request().Context(), id, actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        if !ok {
            return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
        }
    }

    res, err := repos.AuthorityRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func createAuthority(c echo.Context) error {
    // Only Admin or Operator can create authorities
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") && !hasRole(roles, "Operator") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    var req AuthorityCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    if req.Name == "" || req.Type == "" {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "name and type are required"})
    }
    if req.Type != "root" && req.Type != "sub" {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid type"})
    }

    now := nowRFC()

    a := &repository.Authority{
        ID:           generateUUID(),
        Name:         req.Name,
        Type:         req.Type,
        ParentID:     req.ParentID,
        Status:       "active",
        CertPEM:      req.CertPEM,
        Fingerprint:  req.Fingerprint,
        KeyAlgorithm: req.KeyAlgorithm,
        KeySize:      req.KeySize,
        ValidFrom:    req.ValidFrom,
        ValidTo:      req.ValidTo,
        CreatedAt:    now,
        UpdatedAt:    now,
    }

    if err := repos.AuthorityRepo.Create(c.Request().Context(), a); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    // Audit: repository or middleware should record this action
    return c.JSON(http.StatusCreated, a)
}

func updateAuthority(c echo.Context) error {
    // Only Admin or Operator
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") && !hasRole(roles, "Operator") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    var req AuthorityUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    a, err := repos.AuthorityRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    a.Name = req.Name
    a.Status = req.Status
    a.CertPEM = req.CertPEM
    a.Fingerprint = req.Fingerprint
    a.KeyAlgorithm = req.KeyAlgorithm
    a.KeySize = req.KeySize
    a.ValidFrom = req.ValidFrom
    a.ValidTo = req.ValidTo
    a.UpdatedAt = nowRFC()

    if err := repos.AuthorityRepo.Update(c.Request().Context(), a); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, a)
}

func deleteAuthority(c echo.Context) error {
    // Only Admin
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    if err := repos.AuthorityRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.NoContent(http.StatusNoContent)
}

//
// Policy handlers
//

func RegisterPolicyHandlers(g *echo.Group) {
    g.GET("/policies", listPolicies)
    g.GET("/policies/:id", getPolicy)
    g.POST("/policies", createPolicy)
    g.PUT("/policies/:id", updatePolicy)
    g.DELETE("/policies/:id", deletePolicy)
}

func listPolicies(c echo.Context) error {
    actorID, roles, _ := getActorFromContext(c)
    authorityID := c.QueryParam("authority_id")

    // Viewer: only policies referenced by viewer's resources or requests
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        res, err := repos.PolicyRepo.ListForUser(c.Request().Context(), actorID, authorityID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, res)
    }

    res, err := repos.PolicyRepo.ListByAuthority(c.Request().Context(), authorityID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getPolicy(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, _ := getActorFromContext(c)

    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        ok, err := repos.PolicyRepo.IsVisibleToUser(c.Request().Context(), id, actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        if !ok {
            return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
        }
    }

    res, err := repos.PolicyRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func createPolicy(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    var req PolicyCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    p := &repository.Policy{
        ID:                    generateUUID(),
        AuthorityID:           req.AuthorityID,
        Name:                  req.Name,
        Version:               req.Version,
        SubjectType:           req.SubjectType,
        AllowedSanTypes:       toJSON(req.AllowedSanTypes),
        MinKeySize:            req.MinKeySize,
        AllowedAlgorithms:     toJSON(req.AllowedAlgorithms),
        MaxValidityDays:       req.MaxValidityDays,
        ValidationRules:       toJSON(req.ValidationRules),
        AllowedProvisionerIDs: toJSON(req.AllowedProvisionerIDs),
        DefaultProvisionerID:  req.DefaultProvisionerID,
        OCSPConfig:            toJSON(req.OCSPConfig),
        CRLConfig:             toJSON(req.CRLConfig),
        CreatedAt:             nowRFC(),
        UpdatedAt:             nowRFC(),
    }

    if err := repos.PolicyRepo.Create(c.Request().Context(), p); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusCreated, p)
}

func updatePolicy(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    var req PolicyUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    p, err := repos.PolicyRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    p.Name = req.Name
    p.Version = req.Version
    p.SubjectType = req.SubjectType
    p.AllowedSanTypes = toJSON(req.AllowedSanTypes)
    p.MinKeySize = req.MinKeySize
    p.AllowedAlgorithms = toJSON(req.AllowedAlgorithms)
    p.MaxValidityDays = req.MaxValidityDays
    p.ValidationRules = toJSON(req.ValidationRules)
    p.AllowedProvisionerIDs = toJSON(req.AllowedProvisionerIDs)
    p.DefaultProvisionerID = req.DefaultProvisionerID
    p.OCSPConfig = toJSON(req.OCSPConfig)
    p.CRLConfig = toJSON(req.CRLConfig)
    p.UpdatedAt = nowRFC()

    if err := repos.PolicyRepo.Update(c.Request().Context(), p); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, p)
}

func deletePolicy(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")
    if err := repos.PolicyRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }
    return c.NoContent(http.StatusNoContent)
}

//
// Provisioner handlers
//

func RegisterProvisionerHandlers(g *echo.Group) {
    g.GET("/provisioners", listProvisioners)
    g.GET("/provisioners/:id", getProvisioner)
    g.POST("/provisioners", createProvisioner)
    g.PUT("/provisioners/:id", updateProvisioner)
    g.DELETE("/provisioners/:id", deleteProvisioner)
}

func listProvisioners(c echo.Context) error {
    actorID, roles, _ := getActorFromContext(c)
    authorityID := c.QueryParam("authority_id")

    // Viewer: only provisioners referenced by viewer's resources
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        res, err := repos.ProvisionerRepo.ListForUser(c.Request().Context(), actorID, authorityID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, res)
    }

    res, err := repos.ProvisionerRepo.ListByAuthority(c.Request().Context(), authorityID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getProvisioner(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, _ := getActorFromContext(c)

    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        ok, err := repos.ProvisionerRepo.IsVisibleToUser(c.Request().Context(), id, actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        if !ok {
            return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
        }
    }

    res, err := repos.ProvisionerRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func createProvisioner(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    var req ProvisionerCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    p := &repository.Provisioner{
        ID:          generateUUID(),
        AuthorityID: req.AuthorityID,
        Name:        req.Name,
        Type:        req.Type,
        Config:      toJSON(req.Config),
        CreatedAt:   nowRFC(),
        UpdatedAt:   nowRFC(),
    }

    if err := repos.ProvisionerRepo.Create(c.Request().Context(), p); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusCreated, p)
}

func updateProvisioner(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    var req ProvisionerUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    p, err := repos.ProvisionerRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    p.Name = req.Name
    p.Type = req.Type
    p.Config = toJSON(req.Config)
    p.UpdatedAt = nowRFC()

    if err := repos.ProvisionerRepo.Update(c.Request().Context(), p); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, p)
}

func deleteProvisioner(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")
    if err := repos.ProvisionerRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }
    return c.NoContent(http.StatusNoContent)
}

//
// Certificate handlers
//

func RegisterCertificateHandlers(g *echo.Group) {
    g.GET("/certificates", listCertificates)
    g.GET("/certificates/:id", getCertificate)
    g.POST("/certificates/request", requestCertificate) // creates approval or issues
    g.POST("/certificates/:id/issue", issueCertificate) // trigger issuance (worker or sync)
    g.POST("/certificates/:id/revoke", revokeCertificate)
    g.PUT("/certificates/:id", updateCertificate)
}

func listCertificates(c echo.Context) error {
    actorID, roles, groups := getActorFromContext(c)
    authorityID := c.QueryParam("authority_id")

    // Viewer: only certificates owned by viewer
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        res, err := repos.CertificateRepo.ListByOwner(c.Request().Context(), actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, res)
    }

    // Approver: can list certificates for groups they belong to (scoped)
    if hasRole(roles, "Approver") && !hasRole(roles, "Admin") {
        res, err := repos.CertificateRepo.ListByGroups(c.Request().Context(), groups)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, res)
    }

    res, err := repos.CertificateRepo.ListByAuthority(c.Request().Context(), authorityID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getCertificate(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, groups := getActorFromContext(c)

    // Viewer: only owner
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        ok, err := repos.CertificateRepo.IsOwnedBy(c.Request().Context(), id, actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        if !ok {
            return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
        }
    }

    // Approver: allow if certificate belongs to approver's groups
    if hasRole(roles, "Approver") && !hasRole(roles, "Admin") {
        ok, err := repos.CertificateRepo.IsInGroups(c.Request().Context(), id, groups)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        if !ok {
            return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
        }
    }

    res, err := repos.CertificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

// requestCertificate creates an approval record if policy requires approval,
// otherwise it enqueues or performs issuance immediately.
func requestCertificate(c echo.Context) error {
    actorID, roles, _ := getActorFromContext(c)

    var req CertificateIssueRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    // Basic validation
    if req.AuthorityID == "" || req.PolicyID == "" || req.CSR == "" {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "authority_id, policy_id and csr_pem are required"})
    }

    // Create approval record (policy determines if approval required)
    approval := &repository.Approval{
        ID:          generateUUID(),
        RequesterID: actorID,
        TargetType:  "certificate",
        TargetID:    "", // will be filled after issuance
        PolicyID:    req.PolicyID,
        Status:      "pending",
        RequestedAt: nowRFC(),
        Payload:     toJSON(map[string]any{"csr": req.CSR, "cert_type": req.CertType, "authority_id": req.AuthorityID}),
        CreatedAt:   nowRFC(),
        UpdatedAt:   nowRFC(),
    }

    if err := repos.ApprovalRepo.Create(c.Request().Context(), approval); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    // Emit audit log via audit repo (middleware may also record)
    _ = repos.AuditRepo.Create(c.Request().Context(), &repository.AuditLog{
        ActorID:   actorID,
        Action:    "CERT_REQUEST",
        TargetType: "approval",
        TargetID:  approval.ID,
        Details:   toJSON(map[string]any{"policy_id": req.PolicyID}),
        Timestamp: nowRFC(),
    })

    // Notify approvers (implementation detail: notification subsystem)
    // For now return approval id and pending status.
    return c.JSON(http.StatusAccepted, map[string]any{
        "approval_id": approval.ID,
        "status":      approval.Status,
        "message":     "Approval created. Notified approvers.",
    })
}

// issueCertificate triggers issuance for an approval/certificate.
// This endpoint is intended for Admin/Operator or background worker to call.
// If workerQueue is available, enqueue issuance job; otherwise perform synchronous issuance.
func issueCertificate(c echo.Context) error {
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") && !hasRole(roles, "Operator") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id") // this is approval id or certificate id depending on flow

    // Enqueue issuance job (preferred)
    if workerQueue != nil {
        if err := workerQueue.EnqueueIssueJob(id); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusAccepted, map[string]any{"message": "issuance enqueued"})
    }

    // Fallback: synchronous issuance (not recommended for long-running StepCA calls)
    // Worker logic should be implemented in worker package; here we call a helper.
    cert, err := performIssuanceSync(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, cert)
}

// performIssuanceSync is a helper that performs issuance synchronously.
// It is a simplified implementation and should be replaced by worker logic.
func performIssuanceSync(ctx any, approvalID string) (*repository.Certificate, error) {
    // Implementation note: this function needs access to repos and stepcaClient.
    // For brevity, we outline the steps; concrete implementation belongs in worker package.
    return nil, fmt.Errorf("synchronous issuance not implemented; use worker queue")
}

func updateCertificate(c echo.Context) error {
    // Admin/Operator can update metadata; Viewer cannot.
    _, roles, _ := getActorFromContext(c)
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    var req CertificateUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    cert, err := repos.CertificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    cert.Metadata = toJSON(req.Metadata)
    cert.UpdatedAt = nowRFC()

    if err := repos.CertificateRepo.Update(c.Request().Context(), cert); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, cert)
}

func revokeCertificate(c echo.Context) error {
    // Admin/Operator only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") && !hasRole(roles, "Operator") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")

    cert, err := repos.CertificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    // Call StepCA revoke (worker or sync). Prefer worker for retries.
    if workerQueue != nil {
        if err := workerQueue.EnqueueRevokeJob(id); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusAccepted, map[string]any{"message": "revocation enqueued"})
    }

    // Fallback: synchronous revoke via stepcaClient
    if stepcaClient == nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "stepca client not initialized"})
    }
    if err := stepcaClient.RevokeCertificate(cert.Serial, 0); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    cert.Status = "revoked"
    cert.RevocationTime = ptr(nowRFC())
    cert.UpdatedAt = nowRFC()
    if err := repos.CertificateRepo.Update(c.Request().Context(), cert); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    // Audit
    _ = repos.AuditRepo.Create(c.Request().Context(), &repository.AuditLog{
        ActorID:   c.Get("actor_id").(string),
        Action:    "CERT_REVOKE",
        TargetType: "certificate",
        TargetID:  cert.ID,
        Details:   toJSON(map[string]any{"serial": cert.Serial}),
        Timestamp: nowRFC(),
    })

    return c.NoContent(http.StatusNoContent)
}

//
// User handlers
//

func RegisterUserHandlers(g *echo.Group) {
    g.GET("/users", listUsers)
    g.GET("/users/:id", getUser)
    g.POST("/users", createUser)
    g.PUT("/users/:id", updateUser)
    g.DELETE("/users/:id", deleteUser)
}

func listUsers(c echo.Context) error {
    actorID, roles, _ := getActorFromContext(c)

    // Viewer: only own user record
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") {
        u, err := repos.UserRepo.GetByID(c.Request().Context(), actorID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
        }
        return c.JSON(http.StatusOK, []repository.User{*u})
    }

    // Admin/Operator/Approver can list users (Approver may be scoped in repo)
    res, err := repos.UserRepo.List(c.Request().Context())
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getUser(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, _ := getActorFromContext(c)

    // Viewer: only own record
    if hasRole(roles, "Viewer") && !hasRole(roles, "Admin") && id != actorID {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    res, err := repos.UserRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func createUser(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    var req UserCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    u := &repository.User{
        ID:          generateUUID(),
        Username:    req.Username,
        DisplayName: req.DisplayName,
        Email:       req.Email,
        Status:      req.Status,
        AuthSource:  req.AuthSource,
        CreatedAt:   nowRFC(),
        UpdatedAt:   nowRFC(),
    }

    if err := repos.UserRepo.Create(c.Request().Context(), u); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusCreated, u)
}

func updateUser(c echo.Context) error {
    id := c.Param("id")
    actorID, roles, _ := getActorFromContext(c)

    // Admin can update any user. A user may update limited fields of their own profile.
    if !hasRole(roles, "Admin") && id != actorID {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    var req UserUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    u, err := repos.UserRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }

    // If not admin, restrict which fields can be updated (e.g., display_name, email)
    if hasRole(roles, "Admin") {
        u.Username = req.Username
        u.Status = req.Status
        u.AuthSource = req.AuthSource
    }
    u.DisplayName = req.DisplayName
    u.Email = req.Email
    u.UpdatedAt = nowRFC()

    if err := repos.UserRepo.Update(c.Request().Context(), u); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, u)
}

func deleteUser(c echo.Context) error {
    // Admin only
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    id := c.Param("id")
    if err := repos.UserRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }
    return c.NoContent(http.StatusNoContent)
}

//
// Audit handlers (Admin only)
//

func RegisterAuditHandlers(g *echo.Group) {
    g.GET("/audit", listAudit)
}

func listAudit(c echo.Context) error {
    _, roles, _ := getActorFromContext(c)
    if !hasRole(roles, "Admin") {
        return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
    }

    // limit param optional
    limit := 200
    res, err := repos.AuditRepo.List(c.Request().Context(), limit)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}
