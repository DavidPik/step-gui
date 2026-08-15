package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    "github.com/jmoiron/sqlx"
)

// Provisioner represents a StepCA provisioner configuration stored in the DB.
type Provisioner struct {
    ID          string  `db:"id"`
    AuthorityID string  `db:"authority_id"`
    Name        string  `db:"name"`
    Type        string  `db:"type"`
    Config      string  `db:"config"` // JSON string
    CreatedAt   string  `db:"created_at"`
    UpdatedAt   string  `db:"updated_at"`
    // Optional: metadata parsed from Config can be added by callers if needed.
}

// ProvisionerRepository defines persistence operations used by API and workers.
//
// Additional helper methods support Viewer scoping and visibility checks:
// - ListForUser returns provisioners visible to a specific user (their authority scope).
// - IsVisibleToUser checks whether a provisioner is visible to a user.
type ProvisionerRepository interface {
    Create(ctx context.Context, p *Provisioner) error
    GetByID(ctx context.Context, id string) (*Provisioner, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Provisioner, error)
    Update(ctx context.Context, p *Provisioner) error
    Delete(ctx context.Context, id string) error

    // Visibility helpers
    ListForUser(ctx context.Context, userID string, authorityID string) ([]Provisioner, error)
    IsVisibleToUser(ctx context.Context, provisionerID string, userID string) (bool, error)
}

type provisionerRepository struct {
    db *sqlx.DB
}

// NewProvisionerRepository constructs a MariaDB-backed ProvisionerRepository.
func NewProvisionerRepository(db *sqlx.DB) ProvisionerRepository {
    return &provisionerRepository{db: db}
}

// Create inserts a new provisioner record.
func (r *provisionerRepository) Create(ctx context.Context, p *Provisioner) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if p.CreatedAt == "" {
        p.CreatedAt = now
    }
    p.UpdatedAt = now

    // Validate Config is valid JSON (store as string)
    if p.Config != "" {
        var tmp interface{}
        if err := json.Unmarshal([]byte(p.Config), &tmp); err != nil {
            return fmt.Errorf("invalid provisioner config JSON: %w", err)
        }
    }

    query := `
INSERT INTO provisioners
(id, authority_id, name, type, config, created_at, updated_at)
VALUES
(:id, :authority_id, :name, :type, :config, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":           p.ID,
        "authority_id": p.AuthorityID,
        "name":         p.Name,
        "type":         p.Type,
        "config":       p.Config,
        "created_at":   p.CreatedAt,
        "updated_at":   p.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a provisioner by id.
func (r *provisionerRepository) GetByID(ctx context.Context, id string) (*Provisioner, error) {
    var p Provisioner
    query := `SELECT id, authority_id, name, type, config, created_at, updated_at FROM provisioners WHERE id = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &p, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("provisioner not found")
        }
        return nil, err
    }
    return &p, nil
}

// ListByAuthority lists provisioners filtered by authority_id (empty returns all).
func (r *provisionerRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Provisioner, error) {
    var list []Provisioner
    var err error
    if authorityID == "" {
        query := `SELECT id, authority_id, name, type, config, created_at, updated_at FROM provisioners ORDER BY name ASC LIMIT 1000`
        err = r.db.SelectContext(ctx, &list, query)
    } else {
        query := `SELECT id, authority_id, name, type, config, created_at, updated_at FROM provisioners WHERE authority_id = ? ORDER BY name ASC`
        err = r.db.SelectContext(ctx, &list, query, authorityID)
    }
    if err != nil {
        return nil, err
    }
    return list, nil
}

// Update updates mutable fields of a provisioner.
func (r *provisionerRepository) Update(ctx context.Context, p *Provisioner) error {
    p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

    // Validate Config JSON if present
    if p.Config != "" {
        var tmp interface{}
        if err := json.Unmarshal([]byte(p.Config), &tmp); err != nil {
            return fmt.Errorf("invalid provisioner config JSON: %w", err)
        }
    }

    query := `
UPDATE provisioners SET
  name = :name,
  type = :type,
  config = :config,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":         p.ID,
        "name":       p.Name,
        "type":       p.Type,
        "config":     p.Config,
        "updated_at": p.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// Delete removes a provisioner record.
func (r *provisionerRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM provisioners WHERE id = ?`, id)
    return err
}

//
// Visibility helpers
//

// ListForUser returns provisioners visible to a given user.
// Visibility rules:
// - Admins (handled by API) see all.
// - Viewers should only see provisioners for authorities they have visibility into.
// This method uses approvals/certificates ownership to determine authority visibility.
func (r *provisionerRepository) ListForUser(ctx context.Context, userID string, authorityID string) ([]Provisioner, error) {
    // If authorityID provided, restrict to that authority after visibility check.
    // Query provisioners where authority_id IN (authorities visible to user)
    // Visible authorities are those that issued certificates to the user or are referenced by approvals requested by the user.
    args := []interface{}{userID, userID, userID}
    authorityFilter := ""
    if authorityID != "" {
        authorityFilter = "AND p.authority_id = ?"
        args = append(args, authorityID)
    }

    query := fmt.Sprintf(`
SELECT DISTINCT p.id, p.authority_id, p.name, p.type, p.config, p.created_at, p.updated_at
FROM provisioners p
WHERE EXISTS (
    SELECT 1 FROM certificates c
    LEFT JOIN approvals a ON c.approval_id = a.id
    WHERE p.authority_id = c.authority_id
      AND (c.owner_user_id = ? OR a.requester_id = ?)
)
OR EXISTS (
    SELECT 1 FROM approvals a2
    WHERE p.authority_id = a2.policy_id OR p.authority_id = a2.policy_id
    AND a2.requester_id = ?
)
%s
ORDER BY p.name ASC
`, authorityFilter)

    var list []Provisioner
    if err := r.db.SelectContext(ctx, &list, query, args...); err != nil {
        return nil, err
    }
    return list, nil
}

// IsVisibleToUser checks whether a provisioner is visible to a user.
// Returns true if the user owns a certificate issued by the provisioner's authority or requested an approval referencing it.
func (r *provisionerRepository) IsVisibleToUser(ctx context.Context, provisionerID string, userID string) (bool, error) {
    query := `
SELECT 1
FROM provisioners p
LEFT JOIN certificates c ON p.authority_id = c.authority_id
LEFT JOIN approvals a ON c.approval_id = a.id
WHERE p.id = ?
  AND (c.owner_user_id = ? OR a.requester_id = ?)
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, provisionerID, userID, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}
