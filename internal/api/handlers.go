package api

import (
    "net/http"
    "time"

    "github.com/labstack/echo/v4"
    "step-gui/internal/db/repository"
)

var authorityRepo repository.AuthorityRepository

func InitRepositories(ar repository.AuthorityRepository) {
    authorityRepo = ar
}

// TODO: nahradit skutečným generátorem UUID
func generateUUID() string {
    return "TODO-UUID"
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

func RegisterAuthorityHandlers(g *echo.Group) {
    g.GET("/authorities", listAuthorities)
    g.GET("/authorities/:id", getAuthority)
    g.POST("/authorities", createAuthority)
    g.PUT("/authorities/:id", updateAuthority)
    g.DELETE("/authorities/:id", deleteAuthority)
}

func listAuthorities(c echo.Context) error {
    res, err := authorityRepo.List(c.Request().Context())
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func getAuthority(c echo.Context) error {
    id := c.Param("id")
    res, err := authorityRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, res)
}

func createAuthority(c echo.Context) error {
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

    now := time.Now().Format(time.RFC3339)

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

    if err := authorityRepo.Create(c.Request().Context(), a); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusCreated, a)
}

func updateAuthority(c echo.Context) error {
    id := c.Param("id")

    var req AuthorityUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
    }

    a, err := authorityRepo.GetByID(c.Request().Context(), id)
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
    a.UpdatedAt = time.Now().Format(time.RFC3339)

    if err := authorityRepo.Update(c.Request().Context(), a); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, a)
}

func deleteAuthority(c echo.Context) error {
    id := c.Param("id")

    if err := authorityRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    return c.NoContent(http.StatusNoContent)
}

func RegisterPolicyHandlers(g *echo.Group) {
    g.GET("/policies", listPolicies)
    g.GET("/policies/:id", getPolicy)
    g.POST("/policies", createPolicy)
    g.PUT("/policies/:id", updatePolicy)
    g.DELETE("/policies/:id", deletePolicy)
}

func listPolicies(c echo.Context) error {
    res, err := policyRepo.ListByAuthority(c.Request().Context(), c.QueryParam("authority_id"))
    if err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func getPolicy(c echo.Context) error {
    id := c.Param("id")
    res, err := policyRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func createPolicy(c echo.Context) error {
    var req PolicyCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
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

    if err := policyRepo.Create(c.Request().Context(), p); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(201, p)
}

func updatePolicy(c echo.Context) error {
    id := c.Param("id")

    var req PolicyUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
    }

    p, err := policyRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
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

    if err := policyRepo.Update(c.Request().Context(), p); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(200, p)
}

func deletePolicy(c echo.Context) error {
    id := c.Param("id")
    if err := policyRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }
    return c.NoContent(204)
}

func RegisterProvisionerHandlers(g *echo.Group) {
    g.GET("/provisioners", listProvisioners)
    g.GET("/provisioners/:id", getProvisioner)
    g.POST("/provisioners", createProvisioner)
    g.PUT("/provisioners/:id", updateProvisioner)
    g.DELETE("/provisioners/:id", deleteProvisioner)
}

func listProvisioners(c echo.Context) error {
    res, err := provisionerRepo.ListByAuthority(c.Request().Context(), c.QueryParam("authority_id"))
    if err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func getProvisioner(c echo.Context) error {
    id := c.Param("id")
    res, err := provisionerRepo.GetByID(c.Request.Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func createProvisioner(c echo.Context) error {
    var req ProvisionerCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
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

    if err := provisionerRepo.Create(c.Request().Context(), p); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(201, p)
}

func updateProvisioner(c echo.Context) error {
    id := c.Param("id")

    var req ProvisionerUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
    }

    p, err := provisionerRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }

    p.Name = req.Name
    p.Type = req.Type
    p.Config = toJSON(req.Config)
    p.UpdatedAt = nowRFC()

    if err := provisionerRepo.Update(c.Request().Context(), p); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(200, p)
}

func deleteProvisioner(c echo.Context) error {
    id := c.Param("id")
    if err := provisionerRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }
    return c.NoContent(204)
}

func RegisterCertificateHandlers(g *echo.Group) {
    g.GET("/certificates", listCertificates)
    g.GET("/certificates/:id", getCertificate)
    g.POST("/certificates", issueCertificate)
    g.PUT("/certificates/:id", updateCertificate)
    g.DELETE("/certificates/:id", revokeCertificate)
}

func listCertificates(c echo.Context) error {
    res, err := certificateRepo.ListByAuthority(c.Request().Context(), c.QueryParam("authority_id"))
    if err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func getCertificate(c echo.Context) error {
    id := c.Param("id")
    res, err := certificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func issueCertificate(c echo.Context) error {
    var req CertificateIssueRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
    }

    // TODO: call step-ca client in FÁZE 4
    // zatím jen uložíme placeholder

    cert := &repository.Certificate{
        ID:           generateUUID(),
        AuthorityID:  req.AuthorityID,
        PolicyID:     req.PolicyID,
        SerialNumber: "TODO-SERIAL",
        CertPEM:      "TODO-CERT",
        Status:       "valid",
        IssuedAt:     nowRFC(),
        ExpiresAt:    nowRFC(),
        IssueMethod:  req.IssueMethod,
        CreatedAt:    nowRFC(),
        UpdatedAt:    nowRFC(),
    }

    if err := certificateRepo.Create(c.Request().Context(), cert); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(201, cert)
}

func updateCertificate(c echo.Context) error {
    id := c.Param("id")

    var req CertificateUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
    }

    cert, err := certificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }

    cert.Metadata = toJSON(req.Metadata)
    cert.UpdatedAt = nowRFC()

    if err := certificateRepo.Update(c.Request().Context(), cert); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(200, cert)
}

func revokeCertificate(c echo.Context) error {
    id := c.Param("id")

    cert, err := certificateRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }

    cert.Status = "revoked"
    cert.RevocationTime = ptr(nowRFC())
    cert.UpdatedAt = nowRFC()

    if err := certificateRepo.Update(c.Request().Context(), cert); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.NoContent(204)
}

func RegisterUserHandlers(g *echo.Group) {
    g.GET("/users", listUsers)
    g.GET("/users/:id", getUser)
    g.POST("/users", createUser)
    g.PUT("/users/:id", updateUser)
    g.DELETE("/users/:id", deleteUser)
}

func listUsers(c echo.Context) error {
    res, err := userRepo.List(c.Request().Context())
    if err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func getUser(c echo.Context) error {
    id := c.Param("id")
    res, err := userRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}

func createUser(c echo.Context) error {
    var req UserCreateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
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

    if err := userRepo.Create(c.Request().Context(), u); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(201, u)
}

func updateUser(c echo.Context) error {
    id := c.Param("id")

    var req UserUpdateRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid JSON"})
    }

    u, err := userRepo.GetByID(c.Request().Context(), id)
    if err != nil {
        return c.JSON(404, map[string]string{"error": err.Error()})
    }

    u.Username = req.Username
    u.DisplayName = req.DisplayName
    u.Email = req.Email
    u.Status = req.Status
    u.AuthSource = req.AuthSource
    u.UpdatedAt = nowRFC()

    if err := userRepo.Update(c.Request().Context(), u); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }

    return c.JSON(200, u)
}

func deleteUser(c echo.Context) error {
    id := c.Param("id")
    if err := userRepo.Delete(c.Request().Context(), id); err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }
    return c.NoContent(204)
}

func RegisterAuditHandlers(g *echo.Group) {
    g.GET("/audit", listAudit)
}

func listAudit(c echo.Context) error {
    res, err := auditRepo.List(c.Request().Context(), 200)
    if err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    return c.JSON(200, res)
}
