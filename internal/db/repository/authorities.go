package repository

import (
    "context"
    "database/sql"
    "fmt"
    "strings"
    "time"

    "github.com/jmoiron/sqlx"
)

// Authority represents a CA authority record stored in MariaDB.
type Authority struct {
    ID           string  `db:"id"`
    Name         string  `db:"name"`
    Type         string  `db:"type"` // "root" | "sub"
    ParentID     *string `db:"parent_id"`
    Status       string  `db:"status"`
    CertPEM      *string `db:"cert_pem"`
    Fingerprint  *string `db:"fingerprint"`
    KeyAlgorithm *string `db:"key_algorithm"`
    KeySize      *int    `db:"key_size"`
    ValidFrom    *string `db:"valid_from"`
    ValidTo      *string `db:"valid_to"`
    CreatedAt    string  `db:"created_at"`
    UpdatedAt    string  `db:"updated_at"`
}

// AuthorityRepository defines persistence operations used by API and workers.
//
// Additional helper methods support Viewer scoping and visibility checks:
// - ListForUser(ctx, userID) returns authorities visible to a specific viewer.
// - IsVisibleToUser(ctx, authorityID, userID) checks whether an authority is visible to a user.
type AuthorityRepository interface {
    Create(ctx context.Context, a *Authority) error
    GetByID(ctx context.Context, id string) (*Authority, error)
    List(ctx context.Context) ([]Authority, error)
    Update(ctx context.Context, a *Authority) error
    Delete(ctx context.Context, id string) error

    // Visibility helpers used by API Viewer scoping
    ListForUser(ctx context.Context, userID string) ([]Authority, error)
    IsVisibleToUser(ctx context.Context, authorityID string, userID string) (bool, error)
}

type authorityRepository struct {
    db *sqlx.DB
}

// NewAuthorityRepository constructs a MariaDB-backed AuthorityRepository.
func NewAuthorityRepository(db *sqlx.DB) AuthorityRepository {
    return &authorityRepository{db: db}
}

// Create inserts a new authority record.
func (r *authorityRepository) Create(ctx context.Context, a *Authority) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if a.CreatedAt == "" {
        a.CreatedAt = now
    }
    a.UpdatedAt = now

    query := `
INSERT INTO authorities
(id, name, type, parent_id, status, cert_pem, fingerprint, key_algorithm, key_size, valid_from, valid_to, created_at, updated_at)
VALUES
(:id, :name, :type, :parent_id, :status, :cert_pem, :fingerprint, :key_algorithm, :key_size, :valid_from, :valid_to, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":            a.ID,
        "name":          a.Name,
        "type":          a.Type,
        "parent_id":     a.ParentID,
        "status":        a.Status,
        "cert_pem":      a.CertPEM,
        "fingerprint":   a.Fingerprint,
        "key_algorithm": a.KeyAlgorithm,
        "key_size":      a.KeySize,
        "valid_from":    a.ValidFrom,
        "valid_to":      a.ValidTo,
        "created_at":    a.CreatedAt,
        "updated_at":    a.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns an authority by id.
func (r *authorityRepository) GetByID(ctx context.Context, id string) (*Authority, error) {
    var a Authority
    query := `
SELECT id, name, type, parent_id, status, cert_pem, fingerprint, key_algorithm, key_size, valid_from, valid_to, created_at, updated_at
FROM authorities
WHERE id = ? LIMIT 1
`
    if err := r.db.GetContext(ctx, &a, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("authority not found")
        }
        return nil, err
    }
    return &a, nil
}

// List returns all authorities (Admin view). Caller should enforce RBAC.
func (r *authorityRepository) List(ctx context.Context) ([]Authority, error) {
    var list []Authority
    query := `
SELECT id, name, type, parent_id, status, cert_pem, fingerprint, key_algorithm, key_size, valid_from, valid_to, created_at, updated_at
FROM authorities
ORDER BY name ASC
LIMIT 1000
`
    if err := r.db.SelectContext(ctx, &list, query); err != nil {
        return nil, err
    }
    return list, nil
}

// Update updates mutable fields of an authority.
func (r *authorityRepository) Update(ctx context.Context, a *Authority) error {
    a.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    query := `
UPDATE authorities SET
  name = :name,
  type = :type,
  parent_id = :parent_id,
  status = :status,
  cert_pem = :cert_pem,
  fingerprint = :fingerprint,
  key_algorithm = :key_algorithm,
  key_size = :key_size,
  valid_from = :valid_from,
  valid_to = :valid_to,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":            a.ID,
        "name":          a.Name,
        "type":          a.Type,
        "parent_id":     a.ParentID,
        "status":        a.Status,
        "cert_pem":      a.CertPEM,
        "fingerprint":   a.Fingerprint,
        "key_algorithm": a.KeyAlgorithm,
        "key_size":      a.KeySize,
        "valid_from":    a.ValidFrom,
        "valid_to":      a.ValidTo,
        "updated_at":    a.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// Delete removes an authority record.
func (r *authorityRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM authorities WHERE id = ?`, id)
    return err
}

//
// Viewer / scoping helpers
//

// ListForUser returns authorities visible to a given user.
// Visibility rules:
// - Authorities that issued certificates owned by the user.
// - Authorities referenced by approvals requested by the user.
// - Authorities referenced by provisioners/policies the user has access to (best-effort).
func (r *authorityRepository) ListForUser(ctx context.Context, userID string) ([]Authority, error) {
    var list []Authority
    query := `
SELECT DISTINCT auth.id, auth.name, auth.type, auth.parent_id, auth.status, auth.cert_pem, auth.fingerprint, auth.key_algorithm, auth.key_size, auth.valid_from, auth.valid_to, auth.created_at, auth.updated_at
FROM authorities auth
LEFT JOIN certificates c ON auth.id = c.authority_id
LEFT JOIN approvals a ON c.approval_id = a.id
LEFT JOIN provisioners p ON p.authority_id = auth.id
WHERE (c.owner_user_id = ?)
   OR (a.requester_id = ?)
   OR (p.id IS NOT NULL AND EXISTS (
        SELECT 1 FROM approvals a2 WHERE a2.requester_id = ? AND (a2.policy_id = p.authority_id OR a2.policy_id IS NOT NULL)
   ))
ORDER BY auth.name ASC
LIMIT 1000
`
    if err := r.db.SelectContext(ctx, &list, query, userID, userID, userID); err != nil {
        return nil, err
    }
    return list, nil
}

// IsVisibleToUser checks whether an authority is visible to a user.
// Returns true if the user owns a certificate issued by that authority or requested an approval referencing it.
func (r *authorityRepository) IsVisibleToUser(ctx context.Context, authorityID string, userID
