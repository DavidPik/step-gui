package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// Device represents an enrolled device or identity-bound object.
type Device struct {
    ID          string            `db:"id"`
    Name        string            `db:"name"`
    Serial      *string           `db:"serial"`
    OwnerUserID *string           `db:"owner_user_id"`
    GroupID     *string           `db:"group_id"`
    Metadata    map[string]string `db:"metadata"` // stored as JSON in DB
    Status      string            `db:"status"`
    CreatedAt   string            `db:"created_at"`
    UpdatedAt   string            `db:"updated_at"`
}

// DeviceRepository defines persistence operations for devices and helpers used by RBAC/viewer scoping.
type DeviceRepository interface {
    Create(ctx context.Context, d *Device) error
    GetByID(ctx context.Context, id string) (*Device, error)
    ListByGroup(ctx context.Context, groupID string) ([]Device, error)
    ListByOwner(ctx context.Context, ownerUserID string) ([]Device, error)
    ListForUser(ctx context.Context, userID string) ([]Device, error)
    Update(ctx context.Context, d *Device) error
    Delete(ctx context.Context, id string) error

    // Helpers
    IsOwnedByUser(ctx context.Context, deviceID string, userID string) (bool, error)
    IsVisibleToUser(ctx context.Context, deviceID string, userID string) (bool, error)
}

type deviceRepository struct {
    db *sqlx.DB
}

// NewDeviceRepository constructs a MariaDB-backed DeviceRepository.
func NewDeviceRepository(db *sqlx.DB) DeviceRepository {
    return &deviceRepository{db: db}
}

// Create inserts a new device record. Metadata will be marshaled to JSON.
func (r *deviceRepository) Create(ctx context.Context, d *Device) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if d.CreatedAt == "" {
        d.CreatedAt = now
    }
    d.UpdatedAt = now

    metaJSON := "{}"
    if d.Metadata != nil {
        if b, err := json.Marshal(d.Metadata); err == nil {
            metaJSON = string(b)
        } else {
            return fmt.Errorf("marshal metadata: %w", err)
        }
    }

    query := `
INSERT INTO devices
(id, name, serial, owner_user_id, group_id, metadata, status, created_at, updated_at)
VALUES
(:id, :name, :serial, :owner_user_id, :group_id, :metadata, :status, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":            d.ID,
        "name":          d.Name,
        "serial":        d.Serial,
        "owner_user_id": d.OwnerUserID,
        "group_id":      d.GroupID,
        "metadata":      metaJSON,
        "status":        d.Status,
        "created_at":    d.CreatedAt,
        "updated_at":    d.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a device by id.
func (r *deviceRepository) GetByID(ctx context.Context, id string) (*Device, error) {
    var row struct {
        ID          string          `db:"id"`
        Name        string          `db:"name"`
        Serial      sql.NullString  `db:"serial"`
        OwnerUserID sql.NullString  `db:"owner_user_id"`
        GroupID     sql.NullString  `db:"group_id"`
        Metadata    sql.NullString  `db:"metadata"`
        Status      string          `db:"status"`
        CreatedAt   string          `db:"created_at"`
        UpdatedAt   string          `db:"updated_at"`
    }
    query := `SELECT id, name, serial, owner_user_id, group_id, metadata, status, created_at, updated_at FROM devices WHERE id = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &row, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("device not found")
        }
        return nil, err
    }

    d := &Device{
        ID:        row.ID,
        Name:      row.Name,
        Status:    row.Status,
        CreatedAt: row.CreatedAt,
        UpdatedAt: row.UpdatedAt,
        Metadata:  map[string]string{},
    }
    if row.Serial.Valid {
        s := row.Serial.String
        d.Serial = &s
    }
    if row.OwnerUserID.Valid {
        ou := row.OwnerUserID.String
        d.OwnerUserID = &ou
    }
    if row.GroupID.Valid {
        g := row.GroupID.String
        d.GroupID = &g
    }
    if row.Metadata.Valid && row.Metadata.String != "" {
        _ = json.Unmarshal([]byte(row.Metadata.String), &d.Metadata)
    }
    return d, nil
}

// ListByGroup returns devices that belong to a specific group.
func (r *deviceRepository) ListByGroup(ctx context.Context, groupID string) ([]Device, error) {
    var rows []struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Serial      sql.NullString `db:"serial"`
        OwnerUserID sql.NullString `db:"owner_user_id"`
        GroupID     sql.NullString `db:"group_id"`
        Metadata    sql.NullString `db:"metadata"`
        Status      string         `db:"status"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `SELECT id, name, serial, owner_user_id, group_id, metadata, status, created_at, updated_at FROM devices WHERE group_id = ? ORDER BY name ASC LIMIT 1000`
    if err := r.db.SelectContext(ctx, &rows, query, groupID); err != nil {
        return nil, err
    }

    out := make([]Device, 0, len(rows))
    for _, rr := range rows {
        d := Device{
            ID:        rr.ID,
            Name:      rr.Name,
            Status:    rr.Status,
            CreatedAt: rr.CreatedAt,
            UpdatedAt: rr.UpdatedAt,
            Metadata:  map[string]string{},
        }
        if rr.Serial.Valid {
            s := rr.Serial.String
            d.Serial = &s
        }
        if rr.OwnerUserID.Valid {
            ou := rr.OwnerUserID.String
            d.OwnerUserID = &ou
        }
        if rr.GroupID.Valid {
            g := rr.GroupID.String
            d.GroupID = &g
        }
        if rr.Metadata.Valid && rr.Metadata.String != "" {
            _ = json.Unmarshal([]byte(rr.Metadata.String), &d.Metadata)
        }
        out = append(out, d)
    }
    return out, nil
}

// ListByOwner returns devices owned by a specific user.
func (r *deviceRepository) ListByOwner(ctx context.Context, ownerUserID string) ([]Device, error) {
    var rows []struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Serial      sql.NullString `db:"serial"`
        OwnerUserID sql.NullString `db:"owner_user_id"`
        GroupID     sql.NullString `db:"group_id"`
        Metadata    sql.NullString `db:"metadata"`
        Status      string         `db:"status"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `SELECT id, name, serial, owner_user_id, group_id, metadata, status, created_at, updated_at FROM devices WHERE owner_user_id = ? ORDER BY name ASC LIMIT 1000`
    if err := r.db.SelectContext(ctx, &rows, query, ownerUserID); err != nil {
        return nil, err
    }

    out := make([]Device, 0, len(rows))
    for _, rr := range rows {
        d := Device{
            ID:        rr.ID,
            Name:      rr.Name,
            Status:    rr.Status,
            CreatedAt: rr.CreatedAt,
            UpdatedAt: rr.UpdatedAt,
            Metadata:  map[string]string{},
        }
        if rr.Serial.Valid {
            s := rr.Serial.String
            d.Serial = &s
        }
        if rr.OwnerUserID.Valid {
            ou := rr.OwnerUserID.String
            d.OwnerUserID = &ou
        }
        if rr.GroupID.Valid {
            g := rr.GroupID.String
            d.GroupID = &g
        }
        if rr.Metadata.Valid && rr.Metadata.String != "" {
            _ = json.Unmarshal([]byte(rr.Metadata.String), &d.Metadata)
        }
        out = append(out, d)
    }
    return out, nil
}

// ListForUser returns devices visible to a given user.
// Visibility rules:
// - Devices owned by the user.
// - Devices in groups the user belongs to.
func (r *deviceRepository) ListForUser(ctx context.Context, userID string) ([]Device, error) {
    // We rely on users.groups JSON field to determine group membership.
    query := `
SELECT d.id, d.name, d.serial, d.owner_user_id, d.group_id, d.metadata, d.status, d.created_at, d.updated_at
FROM devices d
LEFT JOIN users u ON u.id = ?
WHERE d.owner_user_id = ?
   OR (d.group_id IS NOT NULL AND JSON_CONTAINS(u.groups, CONCAT('"', d.group_id, '"')))
ORDER BY d.name ASC
LIMIT 1000
`
    var rows []struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Serial      sql.NullString `db:"serial"`
        OwnerUserID sql.NullString `db:"owner_user_id"`
        GroupID     sql.NullString `db:"group_id"`
        Metadata    sql.NullString `db:"metadata"`
        Status      string         `db:"status"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    if err := r.db.SelectContext(ctx, &rows, query, userID, userID); err != nil {
        return nil, err
    }

    out := make([]Device, 0, len(rows))
    for _, rr := range rows {
        d := Device{
            ID:        rr.ID,
            Name:      rr.Name,
            Status:    rr.Status,
            CreatedAt: rr.CreatedAt,
            UpdatedAt: rr.UpdatedAt,
            Metadata:  map[string]string{},
        }
        if rr.Serial.Valid {
            s := rr.Serial.String
            d.Serial = &s
        }
        if rr.OwnerUserID.Valid {
            ou := rr.OwnerUserID.String
            d.OwnerUserID = &ou
        }
        if rr.GroupID.Valid {
            g := rr.GroupID.String
            d.GroupID = &g
        }
        if rr.Metadata.Valid && rr.Metadata.String != "" {
            _ = json.Unmarshal([]byte(rr.Metadata.String), &d.Metadata)
        }
        out = append(out, d)
    }
    return out, nil
}

// Update updates mutable fields of a device.
func (r *deviceRepository) Update(ctx context.Context, d *Device) error {
    d.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

    metaJSON := "{}"
    if d.Metadata != nil {
        if b, err := json.Marshal(d.Metadata); err == nil {
            metaJSON = string(b)
        } else {
            return fmt.Errorf("marshal metadata: %w", err)
        }
    }

    query := `
UPDATE devices SET
  name = :name,
  serial = :serial,
  owner_user_id = :owner_user_id,
  group_id = :group_id,
  metadata = :metadata,
  status = :status,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":            d.ID,
        "name":          d.Name,
        "serial":        d.Serial,
        "owner_user_id": d.OwnerUserID,
        "group_id":      d.GroupID,
        "metadata":      metaJSON,
        "status":        d.Status,
        "updated_at":    d.UpdatedAt,
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
        return fmt.Errorf("device not found")
    }
    return nil
}

// Delete removes a device record.
func (r *deviceRepository) Delete(ctx context.Context, id string) error {
    res, err := r.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("device not found")
    }
    return nil
}

// IsOwnedByUser checks whether the device is owned by the given user.
func (r *deviceRepository) IsOwnedByUser(ctx context.Context, deviceID string, userID string) (bool, error) {
    var owner sql.NullString
    if err := r.db.GetContext(ctx, &owner, `SELECT owner_user_id FROM devices WHERE id = ? LIMIT 1`, deviceID); err != nil {
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

// IsVisibleToUser checks whether a device is visible to a user.
// Visible if user owns it or user is member of the device's group.
func (r *deviceRepository) IsVisibleToUser(ctx context.Context, deviceID string, userID string) (bool, error) {
    query := `
SELECT 1
FROM devices d
LEFT JOIN users u ON u.id = ?
WHERE d.id = ?
  AND (
       d.owner_user_id = ?
    OR (d.group_id IS NOT NULL AND JSON_CONTAINS(u.groups, CONCAT('"', d.group_id, '"')))
  )
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, userID, deviceID, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}
