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

// Certificate represents an issued certificate record stored in MariaDB.
// Field names are chosen to match API handlers (Serial, Status, Metadata, RevocationTime).
type Certificate struct {
    ID               string   `db:"id"`
    AuthorityID      string   `db:"authority_id"`
    Serial           string   `db:"serial_number"`
    Subject          string   `db:"subject"`
    SANs             []string `db:"sans"` // JSON array in DB
    OwnerUserID      *string  `db:"owner_user_id"`
    OwnerDeviceID    *string  `db:"owner_device_id"`
    ProvisionerID    *string  `db:"provisioner_id"`
    PolicyID         *string  `db:"policy_id"`
    IssuedAt         string   `db:"issued_at"`
    NotBefore        *string  `db:"not_before"`
    NotAfter         *string  `db:"not_after"`
    Status           string   `db:"-"` // computed from Revoked flag
    Revoked          bool     `db:"revoked"`
    RevocationTime   *string  `db:"revoked_at"`
    RevocationReason *string  `db:"revocation_reason"`
    PEM              *string  `db:"pem"`
    Metadata         *string  `db:"metadata"` // optional JSON metadata column
    CreatedAt        string   `db:"created_at"`
    UpdatedAt        string   `db:"updated_at"`
}

// CertificateRepository defines persistence operations for certificates.
type CertificateRepository interface {
    Create(ctx context.Context, c *Certificate) error
    GetByID(ctx context.Context, id string) (*Certificate, error)
    GetBySerial(ctx context.Context, authorityID string, serial string) (*Certificate, error)
    ListByOwner(ctx context.Context, ownerUserID string) ([]Certificate, error)
    ListByDevice(ctx context.Context, deviceID string) ([]Certificate, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error)
    ListByGroups(ctx context.Context, groupIDs []string) ([]Certificate, error)
    Revoke(ctx context.Context, id string, reason string) error
    Update(ctx context.Context, c *Certificate) error
    Delete(ctx context.Context, id string) error

    // Helpers used by handlers
    IsOwnedBy(ctx context.Context, certID string, userID string) (bool, error)
    IsInGroups(ctx context.Context, certID string, groupIDs []string) (bool, error)
    ListForUser(ctx context.Context, userID string) ([]Certificate, error)
}

type certificateRepository struct {
    db *sqlx.DB
}

// NewCertificateRepository constructs a MariaDB-backed CertificateRepository.
func NewCertificateRepository(db *sqlx.DB) CertificateRepository {
    return &certificateRepository{db: db}
}

// Create inserts a new certificate record. SANs and Metadata will be marshaled to JSON.
func (r *certificateRepository) Create(ctx context.Context, c *Certificate) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if c.CreatedAt == "" {
        c.CreatedAt = now
    }
    c.UpdatedAt = now
    if c.IssuedAt == "" {
        c.IssuedAt = now
    }

    sansJSON := "[]"
    if c.SANs != nil {
        b, err := json.Marshal(c.SANs)
        if err != nil {
            return fmt.Errorf("marshal sans: %w", err)
        }
        sansJSON = string(b)
    }

    metaJSON := sqlNullStringFromPtr(c.Metadata)

    query := `
INSERT INTO certificates
(id, authority_id, serial_number, subject, sans, owner_user_id, owner_device_id, provisioner_id, policy_id,
 issued_at, not_before, not_after, revoked, revoked_at, revocation_reason, pem, metadata, created_at, updated_at)
VALUES
(:id, :authority_id, :serial_number, :subject, :sans, :owner_user_id, :owner_device_id, :provisioner_id, :policy_id,
 :issued_at, :not_before, :not_after, :revoked, :revoked_at, :revocation_reason, :pem, :metadata, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":                 c.ID,
        "authority_id":       c.AuthorityID,
        "serial_number":      c.Serial,
        "subject":            c.Subject,
        "sans":               sansJSON,
        "owner_user_id":      c.OwnerUserID,
        "owner_device_id":    c.OwnerDeviceID,
        "provisioner_id":     c.ProvisionerID,
        "policy_id":          c.PolicyID,
        "issued_at":          c.IssuedAt,
        "not_before":         c.NotBefore,
        "not_after":          c.NotAfter,
        "revoked":            c.Revoked,
        "revoked_at":         c.RevocationTime,
        "revocation_reason":  c.RevocationReason,
        "pem":                c.PEM,
        "metadata":           metaJSON,
        "created_at":         c.CreatedAt,
        "updated_at":         c.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a certificate by id.
func (r *certificateRepository) GetByID(ctx context.Context, id string) (*Certificate, error) {
    var row struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }
    query := `
SELECT id, authority_id, serial_number, subject, sans, owner_user_id, owner_device_id, provisioner_id, policy_id,
       issued_at, not_before, not_after, revoked, revoked_at, revocation_reason, pem, metadata, created_at, updated_at
FROM certificates
WHERE id = ? LIMIT 1
`
    if err := r.db.GetContext(ctx, &row, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("certificate not found")
        }
        return nil, err
    }

    c := &Certificate{
        ID:          row.ID,
        AuthorityID: row.AuthorityID,
        Serial:      row.SerialNumber,
        Subject:     row.Subject,
        IssuedAt:    row.IssuedAt,
        CreatedAt:   row.CreatedAt,
        UpdatedAt:   row.UpdatedAt,
        SANs:        []string{},
        Revoked:     row.Revoked != 0,
    }
    if row.SANs.Valid && row.SANs.String != "" {
        _ = json.Unmarshal([]byte(row.SANs.String), &c.SANs)
    }
    if row.OwnerUserID.Valid {
        v := row.OwnerUserID.String
        c.OwnerUserID = &v
    }
    if row.OwnerDeviceID.Valid {
        v := row.OwnerDeviceID.String
        c.OwnerDeviceID = &v
    }
    if row.ProvisionerID.Valid {
        v := row.ProvisionerID.String
        c.ProvisionerID = &v
    }
    if row.PolicyID.Valid {
        v := row.PolicyID.String
        c.PolicyID = &v
    }
    if row.NotBefore.Valid {
        v := row.NotBefore.String
        c.NotBefore = &v
    }
    if row.NotAfter.Valid {
        v := row.NotAfter.String
        c.NotAfter = &v
    }
    if row.RevokedAt.Valid {
        v := row.RevokedAt.String
        c.RevocationTime = &v
    }
    if row.RevocationReason.Valid {
        v := row.RevocationReason.String
        c.RevocationReason = &v
    }
    if row.PEM.Valid {
        v := row.PEM.String
        c.PEM = &v
    }
    if row.Metadata.Valid {
        v := row.Metadata.String
        c.Metadata = &v
    }
    // compute Status for compatibility with handlers
    if c.Revoked {
        c.Status = "revoked"
    } else {
        c.Status = "active"
    }
    return c, nil
}

// GetBySerial returns a certificate by authority and serial number.
func (r *certificateRepository) GetBySerial(ctx context.Context, authorityID string, serial string) (*Certificate, error) {
    var id string
    query := `SELECT id FROM certificates WHERE authority_id = ? AND serial_number = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &id, query, authorityID, serial); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("certificate not found")
        }
        return nil, err
    }
    return r.GetByID(ctx, id)
}

// ListByOwner returns certificates owned by a user.
func (r *certificateRepository) ListByOwner(ctx context.Context, ownerUserID string) ([]Certificate, error) {
    var rows []struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }
    query := `
SELECT id, authority_id, serial_number, subject, sans, owner_user_id, owner_device_id, provisioner_id, policy_id,
       issued_at, not_before, not_after, revoked, revoked_at, revocation_reason, pem, metadata, created_at, updated_at
FROM certificates
WHERE owner_user_id = ?
ORDER BY issued_at DESC
LIMIT 1000
`
    if err := r.db.SelectContext(ctx, &rows, query, ownerUserID); err != nil {
        return nil, err
    }
    out := make([]Certificate, 0, len(rows))
    for _, rr := range rows {
        c := Certificate{
            ID:          rr.ID,
            AuthorityID: rr.AuthorityID,
            Serial:      rr.SerialNumber,
            Subject:     rr.Subject,
            IssuedAt:    rr.IssuedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            SANs:        []string{},
            Revoked:     rr.Revoked != 0,
        }
        if rr.SANs.Valid && rr.SANs.String != "" {
            _ = json.Unmarshal([]byte(rr.SANs.String), &c.SANs)
        }
        if rr.OwnerUserID.Valid {
            v := rr.OwnerUserID.String
            c.OwnerUserID = &v
        }
        if rr.OwnerDeviceID.Valid {
            v := rr.OwnerDeviceID.String
            c.OwnerDeviceID = &v
        }
        if rr.ProvisionerID.Valid {
            v := rr.ProvisionerID.String
            c.ProvisionerID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            c.PolicyID = &v
        }
        if rr.NotBefore.Valid {
            v := rr.NotBefore.String
            c.NotBefore = &v
        }
        if rr.NotAfter.Valid {
            v := rr.NotAfter.String
            c.NotAfter = &v
        }
        if rr.RevokedAt.Valid {
            v := rr.RevokedAt.String
            c.RevocationTime = &v
        }
        if rr.RevocationReason.Valid {
            v := rr.RevocationReason.String
            c.RevocationReason = &v
        }
        if rr.PEM.Valid {
            v := rr.PEM.String
            c.PEM = &v
        }
        if rr.Metadata.Valid {
            v := rr.Metadata.String
            c.Metadata = &v
        }
        if c.Revoked {
            c.Status = "revoked"
        } else {
            c.Status = "active"
        }
        out = append(out, c)
    }
    return out, nil
}

// ListByDevice returns certificates associated with a device.
func (r *certificateRepository) ListByDevice(ctx context.Context, deviceID string) ([]Certificate, error) {
    var rows []struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }
    query := `
SELECT id, authority_id, serial_number, subject, sans, owner_user_id, owner_device_id, provisioner_id, policy_id,
       issued_at, not_before, not_after, revoked, revoked_at, revocation_reason, pem, metadata, created_at, updated_at
FROM certificates
WHERE owner_device_id = ?
ORDER BY issued_at DESC
LIMIT 1000
`
    if err := r.db.SelectContext(ctx, &rows, query, deviceID); err != nil {
        return nil, err
    }
    out := make([]Certificate, 0, len(rows))
    for _, rr := range rows {
        c := Certificate{
            ID:          rr.ID,
            AuthorityID: rr.AuthorityID,
            Serial:      rr.SerialNumber,
            Subject:     rr.Subject,
            IssuedAt:    rr.IssuedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            SANs:        []string{},
            Revoked:     rr.Revoked != 0,
        }
        if rr.SANs.Valid && rr.SANs.String != "" {
            _ = json.Unmarshal([]byte(rr.SANs.String), &c.SANs)
        }
        if rr.OwnerUserID.Valid {
            v := rr.OwnerUserID.String
            c.OwnerUserID = &v
        }
        if rr.OwnerDeviceID.Valid {
            v := rr.OwnerDeviceID.String
            c.OwnerDeviceID = &v
        }
        if rr.ProvisionerID.Valid {
            v := rr.ProvisionerID.String
            c.ProvisionerID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            c.PolicyID = &v
        }
        if rr.NotBefore.Valid {
            v := rr.NotBefore.String
            c.NotBefore = &v
        }
        if rr.NotAfter.Valid {
            v := rr.NotAfter.String
            c.NotAfter = &v
        }
        if rr.RevokedAt.Valid {
            v := rr.RevokedAt.String
            c.RevocationTime = &v
        }
        if rr.RevocationReason.Valid {
            v := rr.RevocationReason.String
            c.RevocationReason = &v
        }
        if rr.PEM.Valid {
            v := rr.PEM.String
            c.PEM = &v
        }
        if rr.Metadata.Valid {
            v := rr.Metadata.String
            c.Metadata = &v
        }
        if c.Revoked {
            c.Status = "revoked"
        } else {
            c.Status = "active"
        }
        out = append(out, c)
    }
    return out, nil
}

// ListByAuthority returns certificates issued by an authority.
func (r *certificateRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error) {
    var rows []struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }
    query := `
SELECT id, authority_id, serial_number, subject, sans, owner_user_id, owner_device_id, provisioner_id, policy_id,
       issued_at, not_before, not_after, revoked, revoked_at, revocation_reason, pem, metadata, created_at, updated_at
FROM certificates
WHERE authority_id = ?
ORDER BY issued_at DESC
LIMIT 2000
`
    if err := r.db.SelectContext(ctx, &rows, query, authorityID); err != nil {
        return nil, err
    }
    out := make([]Certificate, 0, len(rows))
    for _, rr := range rows {
        c := Certificate{
            ID:          rr.ID,
            AuthorityID: rr.AuthorityID,
            Serial:      rr.SerialNumber,
            Subject:     rr.Subject,
            IssuedAt:    rr.IssuedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            SANs:        []string{},
            Revoked:     rr.Revoked != 0,
        }
        if rr.SANs.Valid && rr.SANs.String != "" {
            _ = json.Unmarshal([]byte(rr.SANs.String), &c.SANs)
        }
        if rr.OwnerUserID.Valid {
            v := rr.OwnerUserID.String
            c.OwnerUserID = &v
        }
        if rr.OwnerDeviceID.Valid {
            v := rr.OwnerDeviceID.String
            c.OwnerDeviceID = &v
        }
        if rr.ProvisionerID.Valid {
            v := rr.ProvisionerID.String
            c.ProvisionerID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            c.PolicyID = &v
        }
        if rr.NotBefore.Valid {
            v := rr.NotBefore.String
            c.NotBefore = &v
        }
        if rr.NotAfter.Valid {
            v := rr.NotAfter.String
            c.NotAfter = &v
        }
        if rr.RevokedAt.Valid {
            v := rr.RevokedAt.String
            c.RevocationTime = &v
        }
        if rr.RevocationReason.Valid {
            v := rr.RevocationReason.String
            c.RevocationReason = &v
        }
        if rr.PEM.Valid {
            v := rr.PEM.String
            c.PEM = &v
        }
        if rr.Metadata.Valid {
            v := rr.Metadata.String
            c.Metadata = &v
        }
        if c.Revoked {
            c.Status = "revoked"
        } else {
            c.Status = "active"
        }
        out = append(out, c)
    }
    return out, nil
}

// ListByGroups returns certificates that belong to any of the provided group IDs.
// A certificate is considered in a group if:
// - its owner_user_id references a user whose groups JSON contains the group id, OR
// - its owner_device_id references a device whose group_id is in the provided list.
func (r *certificateRepository) ListByGroups(ctx context.Context, groupIDs []string) ([]Certificate, error) {
    if len(groupIDs) == 0 {
        return nil, nil
    }

    // Build device group IN placeholders
    devicePlaceholders := buildInPlaceholders(len(groupIDs))
    deviceArgs := make([]interface{}, 0, len(groupIDs))
    for _, g := range groupIDs {
        deviceArgs = append(deviceArgs, g)
    }

    // Build JSON_CONTAINS conditions for users
    userConditions := make([]string, 0, len(groupIDs))
    userArgs := make([]interface{}, 0, len(groupIDs))
    for _, g := range groupIDs {
        userConditions = append(userConditions, "JSON_CONTAINS(u.groups, ?)")
        userArgs = append(userArgs, fmt.Sprintf(`"%s"`, g))
    }
    userCond := strings.Join(userConditions, " OR ")

    query := fmt.Sprintf(`
SELECT DISTINCT c.id, c.authority_id, c.serial_number, c.subject, c.sans, c.owner_user_id, c.owner_device_id, c.provisioner_id, c.policy_id,
       c.issued_at, c.not_before, c.not_after, c.revoked, c.revoked_at, c.revocation_reason, c.pem, c.metadata, c.created_at, c.updated_at
FROM certificates c
LEFT JOIN users u ON c.owner_user_id = u.id
LEFT JOIN devices d ON c.owner_device_id = d.id
WHERE (%s)
   OR (d.group_id IN (%s))
ORDER BY c.issued_at DESC
LIMIT 2000
`, userCond, devicePlaceholders)

    args := make([]interface{}, 0, len(userArgs)+len(deviceArgs))
    args = append(args, userArgs...)
    args = append(args, deviceArgs...)

    var rows []struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }

    if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
        return nil, err
    }

    out := make([]Certificate, 0, len(rows))
    for _, rr := range rows {
        c := Certificate{
            ID:          rr.ID,
            AuthorityID: rr.AuthorityID,
            Serial:      rr.SerialNumber,
            Subject:     rr.Subject,
            IssuedAt:    rr.IssuedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            SANs:        []string{},
            Revoked:     rr.Revoked != 0,
        }
        if rr.SANs.Valid && rr.SANs.String != "" {
            _ = json.Unmarshal([]byte(rr.SANs.String), &c.SANs)
        }
        if rr.OwnerUserID.Valid {
            v := rr.OwnerUserID.String
            c.OwnerUserID = &v
        }
        if rr.OwnerDeviceID.Valid {
            v := rr.OwnerDeviceID.String
            c.OwnerDeviceID = &v
        }
        if rr.ProvisionerID.Valid {
            v := rr.ProvisionerID.String
            c.ProvisionerID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            c.PolicyID = &v
        }
        if rr.NotBefore.Valid {
            v := rr.NotBefore.String
            c.NotBefore = &v
        }
        if rr.NotAfter.Valid {
            v := rr.NotAfter.String
            c.NotAfter = &v
        }
        if rr.RevokedAt.Valid {
            v := rr.RevokedAt.String
            c.RevocationTime = &v
        }
        if rr.RevocationReason.Valid {
            v := rr.RevocationReason.String
            c.RevocationReason = &v
        }
        if rr.PEM.Valid {
            v := rr.PEM.String
            c.PEM = &v
        }
        if rr.Metadata.Valid {
            v := rr.Metadata.String
            c.Metadata = &v
        }
        if c.Revoked {
            c.Status = "revoked"
        } else {
            c.Status = "active"
        }
        out = append(out, c)
    }
    return out, nil
}

// Revoke marks a certificate as revoked and records reason and timestamp.
func (r *certificateRepository) Revoke(ctx context.Context, id string, reason string) error {
    now := time.Now().UTC().Format(time.RFC3339)
    query := `
UPDATE certificates SET
  revoked = 1,
  revoked_at = :revoked_at,
  revocation_reason = :revocation_reason,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":                id,
        "revoked_at":        now,
        "revocation_reason": reason,
        "updated_at":        now,
    }
    res, err := r.db.NamedExecContext(ctx, query, params)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("certificate not found")
    }
    return nil
}

// Update updates mutable fields of a certificate (PEM, metadata-like fields).
func (r *certificateRepository) Update(ctx context.Context, c *Certificate) error {
    c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

    sansJSON := "[]"
    if c.SANs != nil {
        b, err := json.Marshal(c.SANs)
        if err != nil {
            return fmt.Errorf("marshal sans: %w", err)
        }
        sansJSON = string(b)
    }

    metaJSON := sqlNullStringFromPtr(c.Metadata)

    query := `
UPDATE certificates SET
  subject = :subject,
  sans = :sans,
  owner_user_id = :owner_user_id,
  owner_device_id = :owner_device_id,
  provisioner_id = :provisioner_id,
  policy_id = :policy_id,
  not_before = :not_before,
  not_after = :not_after,
  pem = :pem,
  revoked = :revoked,
  revoked_at = :revoked_at,
  revocation_reason = :revocation_reason,
  metadata = :metadata,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":                c.ID,
        "subject":           c.Subject,
        "sans":              sansJSON,
        "owner_user_id":     c.OwnerUserID,
        "owner_device_id":   c.OwnerDeviceID,
        "provisioner_id":    c.ProvisionerID,
        "policy_id":         c.PolicyID,
        "not_before":        c.NotBefore,
        "not_after":         c.NotAfter,
        "pem":               c.PEM,
        "revoked":           c.Revoked,
        "revoked_at":        c.RevocationTime,
        "revocation_reason": c.RevocationReason,
        "metadata":          metaJSON,
        "updated_at":        c.UpdatedAt,
    }
    res, err := r.db.NamedExecContext(ctx, query, params)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("certificate not found")
    }
    return nil
}

// Delete removes a certificate record.
func (r *certificateRepository) Delete(ctx context.Context, id string) error {
    res, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("certificate not found")
    }
    return nil
}

//
// Visibility / helper methods
//

// IsOwnedBy checks whether the certificate is owned by the given user.
func (r *certificateRepository) IsOwnedBy(ctx context.Context, certID string, userID string) (bool, error) {
    var owner sql.NullString
    if err := r.db.GetContext(ctx, &owner, `SELECT owner_user_id FROM certificates WHERE id = ? LIMIT 1`, certID); err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    if !owner.Valid {
        return false, nil
    }
    return owner.String == userID, nil
}

// IsInGroups checks whether a certificate belongs to any of the provided groups.
// It returns true if the certificate's owner_user_id references a user whose groups JSON contains any group,
// or if the certificate's owner_device_id references a device whose group_id is in the provided list.
func (r *certificateRepository) IsInGroups(ctx context.Context, certID string, groupIDs []string) (bool, error) {
    if len(groupIDs) == 0 {
        return false, nil
    }

    // Build device IN placeholders
    devicePlaceholders := buildInPlaceholders(len(groupIDs))
    deviceArgs := make([]interface{}, 0, len(groupIDs))
    for _, g := range groupIDs {
        deviceArgs = append(deviceArgs, g)
    }

    // Build JSON_CONTAINS conditions for users
    userConditions := make([]string, 0, len(groupIDs))
    userArgs := make([]interface{}, 0, len(groupIDs))
    for _, g := range groupIDs {
        userConditions = append(userConditions, "JSON_CONTAINS(u.groups, ?)")
        userArgs = append(userArgs, fmt.Sprintf(`"%s"`, g))
    }
    userCond := strings.Join(userConditions, " OR ")

    query := fmt.Sprintf(`
SELECT 1
FROM certificates c
LEFT JOIN users u ON c.owner_user_id = u.id
LEFT JOIN devices d ON c.owner_device_id = d.id
WHERE c.id = ?
  AND ( (%s) OR (d.group_id IN (%s)) )
LIMIT 1
`, userCond, devicePlaceholders)

    args := make([]interface{}, 0, 1+len(userArgs)+len(deviceArgs))
    args = append(args, certID)
    args = append(args, userArgs...)
    args = append(args, deviceArgs...)

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

// ListForUser returns certificates visible to a given user.
// Visibility rules:
// - Certificates owned by the user.
// - Certificates for devices in groups the user belongs to.
// - Certificates referenced by approvals requested by the user.
func (r *certificateRepository) ListForUser(ctx context.Context, userID string) ([]Certificate, error) {
    var rows []struct {
        ID               string         `db:"id"`
        AuthorityID      string         `db:"authority_id"`
        SerialNumber     string         `db:"serial_number"`
        Subject          string         `db:"subject"`
        SANs             sql.NullString `db:"sans"`
        OwnerUserID      sql.NullString `db:"owner_user_id"`
        OwnerDeviceID    sql.NullString `db:"owner_device_id"`
        ProvisionerID    sql.NullString `db:"provisioner_id"`
        PolicyID         sql.NullString `db:"policy_id"`
        IssuedAt         string         `db:"issued_at"`
        NotBefore        sql.NullString `db:"not_before"`
        NotAfter         sql.NullString `db:"not_after"`
        Revoked          int            `db:"revoked"`
        RevokedAt        sql.NullString `db:"revoked_at"`
        RevocationReason sql.NullString `db:"revocation_reason"`
        PEM              sql.NullString `db:"pem"`
        Metadata         sql.NullString `db:"metadata"`
        CreatedAt        string         `db:"created_at"`
        UpdatedAt        string         `db:"updated_at"`
    }
    // Join devices and users to allow group-based visibility (devices.group_id vs users.groups JSON).
    query := `
SELECT DISTINCT c.id, c.authority_id, c.serial_number, c.subject, c.sans, c.owner_user_id, c.owner_device_id, c.provisioner_id, c.policy_id,
       c.issued_at, c.not_before, c.not_after, c.revoked, c.revoked_at, c.revocation_reason, c.pem, c.metadata, c.created_at, c.updated_at
FROM certificates c
LEFT JOIN devices d ON c.owner_device_id = d.id
LEFT JOIN users u ON u.id = ?
LEFT JOIN approvals a ON a.id = c.approval_id
WHERE (c.owner_user_id = ?)
   OR (d.group_id IS NOT NULL AND JSON_CONTAINS(u.groups, CONCAT('"', d.group_id, '"')))
   OR (a.requester_id = ?)
ORDER BY c.issued_at DESC
LIMIT 2000
`
    if err := r.db.SelectContext(ctx, &rows, query, userID, userID, userID); err != nil {
        return nil, err
    }
    out := make([]Certificate, 0, len(rows))
    for _, rr := range rows {
        c := Certificate{
            ID:          rr.ID,
            AuthorityID: rr.AuthorityID,
            Serial:      rr.SerialNumber,
            Subject:     rr.Subject,
            IssuedAt:    rr.IssuedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            SANs:        []string{},
            Revoked:     rr.Revoked != 0,
        }
        if rr.SANs.Valid && rr.SANs.String != "" {
            _ = json.Unmarshal([]byte(rr.SANs.String), &c.SANs)
        }
        if rr.OwnerUserID.Valid {
            v := rr.OwnerUserID.String
            c.OwnerUserID = &v
        }
        if rr.OwnerDeviceID.Valid {
            v := rr.OwnerDeviceID.String
            c.OwnerDeviceID = &v
        }
        if rr.ProvisionerID.Valid {
            v := rr.ProvisionerID.String
            c.ProvisionerID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            c.PolicyID = &v
        }
        if rr.NotBefore.Valid {
            v := rr.NotBefore.String
            c.NotBefore = &v
        }
        if rr.NotAfter.Valid {
            v := rr.NotAfter.String
            c.NotAfter = &v
        }
        if rr.RevokedAt.Valid {
            v := rr.RevokedAt.String
            c.RevocationTime = &v
        }
        if rr.RevocationReason.Valid {
            v := rr.RevocationReason.String
            c.RevocationReason = &v
        }
        if rr.PEM.Valid {
            v := rr.PEM.String
            c.PEM = &v
        }
        if rr.Metadata.Valid {
            v := rr.Metadata.String
            c.Metadata = &v
        }
        if c.Revoked {
            c.Status = "revoked"
        } else {
            c.Status = "active"
        }
        out = append(out, c)
    }
    return out, nil
}

//
// Utility helpers
//

// sqlNullStringFromPtr returns either the string value or nil for NamedExec param compatibility.
func sqlNullStringFromPtr(p *string) interface{} {
    if p == nil {
        return nil
    }
    return *p
}

// buildInPlaceholders builds a comma-separated list of '?' placeholders for IN clauses.
func buildInPlaceholders(n int) string {
    if n <= 0 {
        return ""
    }
    return strings.TrimRight(strings.Repeat("?,", n), ",")
}
