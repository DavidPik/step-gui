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
    // TODO
}

func RegisterProvisionerHandlers(g *echo.Group) {
    // TODO
}

func RegisterCertificateHandlers(g *echo.Group) {
    // TODO
}

func RegisterUserHandlers(g *echo.Group) {
    // TODO
}

func RegisterAuditHandlers(g *echo.Group) {
    // TODO
}
