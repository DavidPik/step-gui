package repository

import (
    "context"
    "database/sql"
    "fmt"
    "strings"
    "time"

    "github.com/jmoiron/sqlx"
)

// Certificate represents a certificate record stored in MariaDB.
type Certificate struct {
    ID               string  `db:"id"`
    AuthorityID      string  `db:"authority_id"`
    PolicyID         string  `db:"policy_id"`
    ProvisionerID    *string `db:"provisioner_id"`
    SerialNumber     string  `db:"serial_number"`
    SubjectCN        *string `db:"subject_cn"`
    SubjectO         *string `db:"subject_o"`
    SAN              string  `db:"san"`
    CertPEM          string  `db:"cert_pem"`
    IssuedAt         string  `db:"issued_at"`
    ExpiresAt        string  `db:"expires_at"`
    Status           string  `db:"status"`
    RevocationReason *int    `db:"revocation_reason"`
    RevocationTime   *string `db:"revocation_time"`
    IssueMethod      string  `db:"issue_method"`
    Metadata         *string `db:"metadata"`
    ApprovalID       *string `db:"approval_id"`
    OwnerUserID      *string `db:"owner_user_id"`
    OwnerDeviceID    *string `db:"owner_device_id"`
    CreatedAt        string  `db:"created_at"`
    UpdatedAt        string  `db:"updated_at"`
}

// CertificateRepository defines persistence operations used by the API and workers.
//
// Additional helper methods are included to support Viewer scoping and Approver group scoping:
// - ListForUser(ctx, userID) returns certificates visible to a specific viewer (their own and those referenced by their requests).
// - IsVisibleToUser(ctx, authorityID, userID) checks whether an authority is visible to a user.
// - ListByOwner(ctx, ownerUserID) returns certificates owned by a user.
// - ListByGroups(ctx, groupIDs) returns certificates that belong to devices/users in the provided groups.
// - IsOwnedBy(ctx, certID, userID) checks ownership.
// - IsInGroups(ctx, certID, groupIDs) checks whether a certificate belongs to any of the groups.
type CertificateRepository interface {
    Create(ctx context.Context, c *Certificate) error
    GetByID(ctx context.Context, id string) (*Certificate, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error)
    Update(ctx context.Context, c *Certificate) error
    Delete(ctx context.Context, id string) error

    // Viewer / scoping helpers
    ListForUser(ctx context.Context, userID string) ([]Certificate, error)
    IsVisibleToUser(ctx context.Context, authorityID string, userID string) (bool, error)
    ListByOwner(ctx context.Context, ownerUserID string) ([]Certificate, error)
    ListByGroups(ctx context.Context, groupIDs []string) ([]Certificate, error)
    IsOwnedBy(ctx context.Context, certID string, userID string) (bool, error)
    IsInGroups(ctx context.Context, certID string, groupIDs []string) (bool, error)
}

type certificateRepository struct {
    db *sqlx.DB
}

// NewCertificateRepository constructs a MariaDB-backed CertificateRepository.
func NewCertificateRepository(db *sqlx.DB) CertificateRepository {
    return &certificateRepository{db: db}
}

// Create inserts a new certificate record.
func (r *certificateRepository) Create(ctx context.Context, c *Certificate) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if c.CreatedAt == "" {
        c.CreatedAt = now
    }
    c.UpdatedAt = now

    query := `
INSERT INTO certificates
(id, subject, cert_type, authority_id, policy_id, provisioner_id, serial, thumbprint,
 subject_cn, subject_o, san, cert_pem, issued_at, expires_at, status, revocation_reason,
 revocation_time, issue_method, stepca_metadata, approval_id, owner_user_id, owner_device_id,
 created_at, updated_at)
VALUES
(:id, :subject, :cert_type, :authority_id, :policy_id, :provisioner_id, :serial, :thumbprint,
 :subject_cn, :subject_o, :san, :cert_pem, :issued_at, :expires_at, :status, :revocation_reason,
 :revocation_time, :issue_method, :stepca_metadata, :approval_id, :owner_user_id, :owner_device_id,
 :created_at, :updated_at)
`
    // Map fields expected by DB. Some struct fields have different names in DB schema used earlier;
    // ensure DB schema matches these column names or adapt accordingly.
    params := map[string]interface{}{
        "id":               c.ID,
        "subject":          c.SubjectCN, // subject stored as CN in earlier schema; keep compatibility
        "cert_type":        c.IssueMethod,
        "authority_id":     c.AuthorityID,
        "policy_id":        c.PolicyID,
        "provisioner_id":   c.ProvisionerID,
        "serial":           c.SerialNumber,
        "thumbprint":       nil, // optional: thumbprint can be stored in Metadata or stepca_metadata
        "subject_cn":       c.SubjectCN,
        "subject_o":        c.SubjectO,
        "san":              c.SAN,
        "cert_pem":         c.CertPEM,
        "issued_at":        c.IssuedAt,
        "expires_at":       c.ExpiresAt,
        "status":           c.Status,
        "revocation_reason": c.RevocationReason,
        "revocation_time":   c.RevocationTime,
        "issue_method":      c.IssueMethod,
        "stepca_metadata":   c.Metadata,
        "approval_id":       c.ApprovalID,
        "owner_user_id":     c.OwnerUserID,
        "owner_device_id":   c.OwnerDeviceID,
        "created_at":        c.CreatedAt,
        "updated_at":        c.UpdatedAt,
    }

    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a certificate by its ID.
func (r *certificateRepository) GetByID(ctx context.Context, id string) (*Certificate, error) {
    var c Certificate
    query := `SELECT id, authority_id, policy_id, provisioner_id, serial AS serial_number,
                 subject_cn, subject_o, san, cert_pem, issued_at, expires_at, status,
                 revocation_reason, revocation_time, issue_method, stepca_metadata AS metadata,
                 approval_id, owner_user_id, owner_device_id, created_at, updated_at
              FROM certificates WHERE id = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &c, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("certificate not found")
        }
        return nil, err
    }
    return &c, nil
}

// ListByAuthority lists certificates filtered by authority_id (empty returns all).
func (r *certificateRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error) {
    var certs []Certificate
    var err error
    if authorityID == "" {
        query := `SELECT id, authority_id, policy_id, provisioner_id, serial AS serial_number,
                         subject_cn, subject_o, san, cert_pem, issued_at, expires_at, status,
                         revocation_reason, revocation_time, issue_method, stepca_metadata AS metadata,
                         approval_id, owner_user_id, owner_device_id, created_at, updated_at
                  FROM certificates ORDER BY created_at DESC LIMIT 1000`
        err = r.db.SelectContext(ctx, &certs, query)
    } else {
        query := `SELECT id, authority_id, policy_id, provisioner_id, serial AS serial_number,
                         subject_cn, subject_o, san, cert_pem, issued_at, expires_at, status,
                         revocation_reason, revocation_time, issue_method, stepca_metadata AS metadata,
                         approval_id, owner_user_id, owner_device_id, created_at, updated_at
                  FROM certificates WHERE authority_id = ? ORDER BY created_at DESC`
        err = r.db.SelectContext(ctx, &certs, query, authorityID)
    }
    if err != nil {
        return nil, err
    }
    return certs, nil
}

// Update updates mutable fields of a certificate (metadata, status, revocation fields, updated_at).
func (r *certificateRepository) Update(ctx context.Context, c *Certificate) error {
    c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    query := `
UPDATE certificates SET
  subject_cn = :subject_cn,
  subject_o = :subject_o,
  san = :san,
  cert_pem = :cert_pem,
  issued_at = :issued_at,
  expires_at = :expires_at,
  status = :status,
  revocation_reason = :revocation_reason,
  revocation_time = :revocation_time,
  issue_method = :issue_method,
  stepca_metadata = :stepca_metadata,
  approval_id = :approval_id,
  owner_user_id = :owner_user_id,
  owner_device_id = :owner_device_id,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":                c.ID,
        "subject_cn":        c.SubjectCN,
        "subject_o":         c.SubjectO,
        "san":               c.SAN,
        "cert_pem":          c.CertPEM,
        "issued_at":         c.IssuedAt,
        "expires_at":        c.ExpiresAt,
        "status":            c.Status,
        "revocation_reason": c.RevocationReason,
        "revocation_time":   c.RevocationTime,
        "issue_method":      c.IssueMethod,
        "stepca_metadata":   c.Metadata,
        "approval_id":       c.ApprovalID,
        "owner_user_id":     c.OwnerUserID,
        "owner_device_id":   c.OwnerDeviceID,
        "updated_at":        c.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// Delete removes a certificate record.
func (r *certificateRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
    return err
}

//
// Viewer / scoping helpers
//

// ListForUser returns certificates visible to a given user:
// - certificates owned by the user
// - certificates linked to approvals requested by the user
// - certificates for devices owned by the user
func (r *certificateRepository) ListForUser(ctx context.Context, userID string) ([]Certificate, error) {
    var certs []Certificate
    query := `
SELECT DISTINCT c.id, c.authority_id, c.policy_id, c.provisioner_id, c.serial AS serial_number,
       c.subject_cn, c.subject_o, c.san, c.cert_pem, c.issued_at, c.expires_at, c.status,
       c.revocation_reason, c.revocation_time, c.issue_method, c.stepca_metadata AS metadata,
       c.approval_id, c.owner_user_id, c.owner_device_id, c.created_at, c.updated_at
FROM certificates c
LEFT JOIN approvals a ON c.approval_id = a.id
LEFT JOIN devices d ON c.owner_device_id = d.id
WHERE c.owner_user_id = ?
   OR a.requester_id = ?
   OR d.owner_user_id = ?
ORDER BY c.created_at DESC
`
    if err := r.db.SelectContext(ctx, &certs, query, userID, userID, userID); err != nil {
        return nil, err
    }
    return certs, nil
}

// IsVisibleToUser checks whether an authority (by id) is visible to a user.
// Returns true if the user owns a certificate issued by that authority or requested an approval referencing it.
func (r *certificateRepository) IsVisibleToUser(ctx context.Context, authorityID string, userID string) (bool, error) {
    query := `
SELECT 1
FROM certificates c
LEFT JOIN approvals a ON c.approval_id = a.id
LEFT JOIN devices d ON c.owner_device_id = d.id
WHERE c.authority_id = ?
  AND (c.owner_user_id = ? OR a.requester_id = ? OR d.owner_user_id = ?)
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, authorityID, userID, userID, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

// ListByOwner returns certificates owned by a specific user.
func (r *certificateRepository) ListByOwner(ctx context.Context, ownerUserID string) ([]Certificate, error) {
    var certs []Certificate
    query := `
SELECT id, authority_id, policy_id, provisioner_id, serial AS serial_number,
       subject_cn, subject_o, san, cert_pem, issued_at, expires_at, status,
       revocation_reason, revocation_time, issue_method, stepca_metadata AS metadata,
       approval_id, owner_user_id, owner_device_id, created_at, updated_at
FROM certificates
WHERE owner_user_id = ?
ORDER BY created_at DESC
`
    if err := r.db.SelectContext(ctx, &certs, query, ownerUserID); err != nil {
        return nil, err
    }
    return certs, nil
}

// ListByGroups returns certificates that belong to devices/users in the provided groups.
// groupIDs is a slice of group id strings.
func (r *certificateRepository) ListByGroups(ctx context.Context, groupIDs []string) ([]Certificate, error) {
    if len(groupIDs) == 0 {
        return []Certificate{}, nil
    }

    // Build placeholders for IN clause
    placeholders := strings.Repeat("?,", len(groupIDs))
    placeholders = strings.TrimRight(placeholders, ",")

    // Query certificates where device.group_id IN (...) OR owner_user has group membership (JSON_CONTAINS)
    // Note: JSON_CONTAINS(users.groups, '["groupid"]') is used for user group membership.
    // We join devices and users to evaluate group membership.
    query := fmt.Sprintf(`
SELECT DISTINCT c.id, c.authority_id, c.policy_id, c.provisioner_id, c.serial AS serial_number,
       c.subject_cn, c.subject_o, c.san, c.cert_pem, c.issued_at, c.expires_at, c.status,
       c.revocation_reason, c.revocation_time, c.issue_method, c.stepca_metadata AS metadata,
       c.approval_id, c.owner_user_id, c.owner_device_id, c.created_at, c.updated_at
FROM certificates c
LEFT JOIN devices d ON c.owner_device_id = d.id
LEFT JOIN users u ON c.owner_user_id = u.id
WHERE (d.group_id IN (%s))
   OR (%s)
ORDER BY c.created_at DESC
`, placeholders, buildJSONContainsOrClause("u.groups", groupIDs))

    // Build args: groupIDs repeated for IN clause; JSON_CONTAINS uses literals in query string, so no args for that part.
    args := make([]interface{}, len(groupIDs))
    for i, g := range groupIDs {
        args[i] = g
    }

    var certs []Certificate
    if err := r.db.SelectContext(ctx, &certs, query, args...); err != nil {
        return nil, err
    }
    return certs, nil
}

// IsOwnedBy checks whether a certificate is owned by a given user (direct owner or device owner).
func (r *certificateRepository) IsOwnedBy(ctx context.Context, certID string, userID string) (bool, error) {
    query := `
SELECT 1
FROM certificates c
LEFT JOIN devices d ON c.owner_device_id = d.id
WHERE c.id = ?
  AND (c.owner_user_id = ? OR d.owner_user_id = ?)
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, certID, userID, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

// IsInGroups checks whether a certificate belongs to any of the provided groups.
func (r *certificateRepository) IsInGroups(ctx context.Context, certID string, groupIDs []string) (bool, error) {
    if len(groupIDs) == 0 {
        return false, nil
    }
    placeholders := strings.Repeat("?,", len(groupIDs))
    placeholders = strings.TrimRight(placeholders, ",")

    query := fmt.Sprintf(`
SELECT 1
FROM certificates c
LEFT JOIN devices d ON c.owner_device_id = d.id
LEFT JOIN users u ON c.owner_user_id = u.id
WHERE c.id = ?
  AND (d.group_id IN (%s) OR %s)
LIMIT 1
`, placeholders, buildJSONContainsOrClause("u.groups", groupIDs))

    args := make([]interface{}, 0, 1+len(groupIDs))
    args = append(args, certID)
    for _, g := range groupIDs {
        args = append(args, g)
    }

    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, args...)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

//
// Helper utilities
//

// buildJSONContainsOrClause builds an OR clause that checks JSON_CONTAINS(field, '["id"]') for each group id.
// Example output: (JSON_CONTAINS(u.groups, '["g1"]') OR JSON_CONTAINS(u.groups, '["g2"]'))
func buildJSONContainsOrClause(jsonField string, ids []string) string {
    parts := make([]string, 0, len(ids))
    for _, id := range ids {
        // JSON_CONTAINS requires a JSON array literal; we embed the id as a string literal.
        parts = append(parts, fmt.Sprintf("JSON_CONTAINS(%s, '\"%s\"')", jsonField, id))
    }
    return "(" + strings.Join(parts, " OR ") + ")"
}
