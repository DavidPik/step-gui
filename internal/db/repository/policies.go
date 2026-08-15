package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// Policy represents a certificate policy stored in MariaDB.
type Policy struct {
    ID                    string  `db:"id"`
    AuthorityID           string  `db:"authority_id"`
    Name                  string  `db:"name"`
    Version               string  `db:"version"`
    SubjectType           string  `db:"subject_type"`
    AllowedSanTypes       *string `db:"allowed_san_types"`       // JSON array
    MinKeySize            *int    `db:"min_key_size"`
    AllowedAlgorithms     *string `db:"allowed_algorithms"`      // JSON array
    MaxValidityDays       *int    `db:"max_validity_days"`
    ValidationRules       *string `db:"validation_rules"`        // JSON object/array
    AllowedProvisionerIDs *string `db:"allowed_provisioner_ids"` // JSON array
    DefaultProvisionerID  *string `db:"default_provisioner_id"`
    OCSPConfig            *string `db:"ocsp_config"` // JSON
    CRLConfig             *string `db:"crl_config"`  // JSON
    CreatedAt             string  `db:"created_at"`
    UpdatedAt             string  `db:"updated_at"`
}

// PolicyRepository defines persistence operations used by API and workers.
//
// Includes visibility helpers used by Viewer scoping:
// - ListByAuthority(ctx, authorityID) lists policies for an authority.
// - ListForUser(ctx, userID, authorityID) returns policies visible to a user (their authorities).
// - IsVisibleToUser(ctx, policyID, userID) checks whether a policy is visible to a user.
type PolicyRepository interface {
    Create(ctx context.Context, p *Policy) error
    GetByID(ctx context.Context, id string) (*Policy, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Policy, error)
    Update(ctx context.Context, p *Policy) error
    Delete(ctx context.Context, id string) error

    // Visibility helpers
    ListForUser(ctx context.Context, userID string, authorityID string) ([]Policy, error)
    IsVisibleToUser(ctx context.Context, policyID string, userID string) (bool, error)
}

type policyRepository struct {
    db *sqlx.DB
}

// NewPolicyRepository constructs a MariaDB-backed PolicyRepository.
func NewPolicyRepository(db *sqlx.DB) PolicyRepository {
    return &policyRepository{db: db}
}

// Create inserts a new policy record.
func (r *policyRepository) Create(ctx context.Context, p *Policy) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if p.CreatedAt == "" {
        p.CreatedAt = now
    }
    p.UpdatedAt = now

    // Validate JSON fields if present
    for _, s := range []*string{p.AllowedSanTypes, p.AllowedAlgorithms, p.ValidationRules, p.AllowedProvisionerIDs, p.OCSPConfig, p.CRLConfig} {
        if s != nil && *s != "" {
            var tmp interface{}
            if err := json.Unmarshal([]byte(*s), &tmp); err != nil {
                return fmt.Errorf("invalid JSON field in policy: %w", err)
            }
        }
    }

    query := `
INSERT INTO policies
(id, authority_id, name, version, subject_type, allowed_san_types, min_key_size, allowed_algorithms,
 max_validity_days, validation_rules, allowed_provisioner_ids, default_provisioner_id, ocsp_config, crl_config,
 created_at, updated_at)
VALUES
(:id, :authority_id, :name, :version, :subject_type, :allowed_san_types, :min_key_size, :allowed_algorithms,
 :max_validity_days, :validation_rules, :allowed_provisioner_ids, :default_provisioner_id, :ocsp_config, :crl_config,
 :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":                       p.ID,
        "authority_id":             p.AuthorityID,
        "name":                     p.Name,
        "version":                  p.Version,
        "subject_type":             p.SubjectType,
        "allowed_san_types":        p.AllowedSanTypes,
        "min_key_size":             p.MinKeySize,
        "allowed_algorithms":       p.AllowedAlgorithms,
        "max_validity_days":        p.MaxValidityDays,
        "validation_rules":         p.ValidationRules,
        "allowed_provisioner_ids":  p.AllowedProvisionerIDs,
        "default_provisioner_id":   p.DefaultProvisionerID,
        "ocsp_config":              p.OCSPConfig,
        "crl_config":               p.CRLConfig,
        "created_at":               p.CreatedAt,
        "updated_at":               p.UpdatedAt,
    }

    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a policy by id.
func (r *policyRepository) GetByID(ctx context.Context, id string) (*Policy, error) {
    var p Policy
    query := `
SELECT id, authority_id, name, version, subject_type, allowed_san_types, min_key_size, allowed_algorithms,
       max_validity_days, validation_rules, allowed_provisioner_ids, default_provisioner_id, ocsp_config, crl_config,
       created_at, updated_at
FROM policies
WHERE id = ? LIMIT 1
`
    if err := r.db.GetContext(ctx, &p, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("policy not found")
        }
        return nil, err
    }
    return &p, nil
}

// ListByAuthority lists policies filtered by authority_id (empty returns all).
func (r *policyRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Policy, error) {
    var list []Policy
    var err error
    if authorityID == "" {
        query := `SELECT id, authority_id, name, version, subject_type, allowed_san_types, min_key_size, allowed_algorithms,
                         max_validity_days, validation_rules, allowed_provisioner_ids, default_provisioner_id, ocsp_config, crl_config,
                         created_at, updated_at
                  FROM policies ORDER BY name ASC LIMIT 1000`
        err = r.db.SelectContext(ctx, &list, query)
    } else {
        query := `SELECT id, authority_id, name, version, subject_type, allowed_san_types, min_key_size, allowed_algorithms,
                         max_validity_days, validation_rules, allowed_provisioner_ids, default_provisioner_id, ocsp_config, crl_config,
                         created_at, updated_at
                  FROM policies WHERE authority_id = ? ORDER BY name ASC`
        err = r.db.SelectContext(ctx, &list, query, authorityID)
    }
    if err != nil {
        return nil, err
    }
    return list, nil
}

// Update updates mutable fields of a policy.
func (r *policyRepository) Update(ctx context.Context, p *Policy) error {
    p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

    // Validate JSON fields if present
    for _, s := range []*string{p.AllowedSanTypes, p.AllowedAlgorithms, p.ValidationRules, p.AllowedProvisionerIDs, p.OCSPConfig, p.CRLConfig} {
        if s != nil && *s != "" {
            var tmp interface{}
            if err := json.Unmarshal([]byte(*s), &tmp); err != nil {
                return fmt.Errorf("invalid JSON field in policy: %w", err)
            }
        }
    }

    query := `
UPDATE policies SET
  name = :name,
  version = :version,
  subject_type = :subject_type,
  allowed_san_types = :allowed_san_types,
  min_key_size = :min_key_size,
  allowed_algorithms = :allowed_algorithms,
  max_validity_days = :max_validity_days,
  validation_rules = :validation_rules,
  allowed_provisioner_ids = :allowed_provisioner_ids,
  default_provisioner_id = :default_provisioner_id,
  ocsp_config = :ocsp_config,
  crl_config = :crl_config,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":                      p.ID,
        "name":                    p.Name,
        "version":                 p.Version,
        "subject_type":            p.SubjectType,
        "allowed_san_types":       p.AllowedSanTypes,
        "min_key_size":            p.MinKeySize,
        "allowed_algorithms":      p.AllowedAlgorithms,
        "max_validity_days":       p.MaxValidityDays,
        "validation_rules":        p.ValidationRules,
        "allowed_provisioner_ids": p.AllowedProvisionerIDs,
        "default_provisioner_id":  p.DefaultProvisionerID,
        "ocsp_config":             p.OCSPConfig,
        "crl_config":              p.CRLConfig,
        "updated_at":              p.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// Delete removes a policy record.
func (r *policyRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
    return err
}

//
// Visibility helpers
//

// ListForUser returns policies visible to a given user.
// Visibility rules:
// - Policies belonging to authorities that issued certificates to the user.
// - Policies referenced by approvals requested by the user.
// If authorityID is provided, results are restricted to that authority.
func (r *policyRepository) ListForUser(ctx context.Context, userID string, authorityID string) ([]Policy, error) {
    args := []interface{}{userID, userID}
    authorityFilter := ""
    if authorityID != "" {
        authorityFilter = "AND p.authority_id = ?"
        args = append(args, authorityID)
    }

    query := `
SELECT DISTINCT p.id, p.authority_id, p.name, p.version, p.subject_type, p.allowed_san_types, p.min_key_size, p.allowed_algorithms,
       p.max_validity_days, p.validation_rules, p.allowed_provisioner_ids, p.default_provisioner_id, p.ocsp_config, p.crl_config,
       p.created_at, p.updated_at
FROM policies p
LEFT JOIN certificates c ON p.authority_id = c.authority_id
LEFT JOIN approvals a ON a.policy_id = p.id OR c.approval_id = a.id
WHERE (c.owner_user_id = ? OR a.requester_id = ?)
` + authorityFilter + `
ORDER BY p.name ASC
LIMIT 1000
`
    var list []Policy
    if err := r.db.SelectContext(ctx, &list, query, args...); err != nil {
        return nil, err
    }
    return list, nil
}

// IsVisibleToUser checks whether a policy is visible to a user.
func (r *policyRepository) IsVisibleToUser(ctx context.Context, policyID string, userID string) (bool, error) {
    query := `
SELECT 1
FROM policies p
LEFT JOIN certificates c ON p.authority_id = c.authority_id
LEFT JOIN approvals a ON a.policy_id = p.id OR c.approval_id = a.id
WHERE p.id = ?
  AND (c.owner_user_id = ? OR a.requester_id = ?)
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, policyID, userID, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}
