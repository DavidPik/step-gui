package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// Role represents an RBAC role stored in MariaDB.
// Permissions is stored as a JSON array in the DB.
type Role struct {
    ID          string   `db:"id"`
    Name        string   `db:"name"`
    Description *string  `db:"description"`
    Permissions []string `db:"permissions"`
    CreatedAt   string   `db:"created_at"`
    UpdatedAt   string   `db:"updated_at"`
}

// RoleRepository defines persistence operations for roles.
type RoleRepository interface {
    Create(ctx context.Context, r *Role) error
    GetByID(ctx context.Context, id string) (*Role, error)
    GetByName(ctx context.Context, name string) (*Role, error)
    List(ctx context.Context) ([]Role, error)
    Update(ctx context.Context, r *Role) error
    Delete(ctx context.Context, id string) error
}

type roleRepository struct {
    db *sqlx.DB
}

// NewRoleRepository constructs a MariaDB-backed RoleRepository.
func NewRoleRepository(db *sqlx.DB) RoleRepository {
    return &roleRepository{db: db}
}

// Create inserts a new role record. Permissions will be marshaled to JSON.
func (r *roleRepository) Create(ctx context.Context, role *Role) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if role.CreatedAt == "" {
        role.CreatedAt = now
    }
    role.UpdatedAt = now

    permsJSON, err := json.Marshal(role.Permissions)
    if err != nil {
        return fmt.Errorf("marshal permissions: %w", err)
    }

    query := `
INSERT INTO roles
(id, name, description, permissions, created_at, updated_at)
VALUES
(:id, :name, :description, :permissions, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":          role.ID,
        "name":        role.Name,
        "description": role.Description,
        "permissions": string(permsJSON),
        "created_at":  role.CreatedAt,
        "updated_at":  role.UpdatedAt,
    }

    _, err = r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a role by id.
func (r *roleRepository) GetByID(ctx context.Context, id string) (*Role, error) {
    var row struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Description sql.NullString `db:"description"`
        Permissions sql.NullString `db:"permissions"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `SELECT id, name, description, permissions, created_at, updated_at FROM roles WHERE id = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &row, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("role not found")
        }
        return nil, err
    }

    role := &Role{
        ID:        row.ID,
        Name:      row.Name,
        CreatedAt: row.CreatedAt,
        UpdatedAt: row.UpdatedAt,
    }
    if row.Description.Valid {
        role.Description = &row.Description.String
    }
    if row.Permissions.Valid && row.Permissions.String != "" {
        _ = json.Unmarshal([]byte(row.Permissions.String), &role.Permissions)
    }
    return role, nil
}

// GetByName returns a role by name.
func (r *roleRepository) GetByName(ctx context.Context, name string) (*Role, error) {
    var row struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Description sql.NullString `db:"description"`
        Permissions sql.NullString `db:"permissions"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `SELECT id, name, description, permissions, created_at, updated_at FROM roles WHERE name = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &row, query, name); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("role not found")
        }
        return nil, err
    }

    role := &Role{
        ID:        row.ID,
        Name:      row.Name,
        CreatedAt: row.CreatedAt,
        UpdatedAt: row.UpdatedAt,
    }
    if row.Description.Valid {
        role.Description = &row.Description.String
    }
    if row.Permissions.Valid && row.Permissions.String != "" {
        _ = json.Unmarshal([]byte(row.Permissions.String), &role.Permissions)
    }
    return role, nil
}

// List returns all roles ordered by name.
func (r *roleRepository) List(ctx context.Context) ([]Role, error) {
    var rows []struct {
        ID          string         `db:"id"`
        Name        string         `db:"name"`
        Description sql.NullString `db:"description"`
        Permissions sql.NullString `db:"permissions"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `SELECT id, name, description, permissions, created_at, updated_at FROM roles ORDER BY name ASC LIMIT 1000`
    if err := r.db.SelectContext(ctx, &rows, query); err != nil {
        return nil, err
    }

    out := make([]Role, 0, len(rows))
    for _, rr := range rows {
        role := Role{
            ID:        rr.ID,
            Name:      rr.Name,
            CreatedAt: rr.CreatedAt,
            UpdatedAt: rr.UpdatedAt,
        }
        if rr.Description.Valid {
            role.Description = &rr.Description.String
        }
        if rr.Permissions.Valid && rr.Permissions.String != "" {
            _ = json.Unmarshal([]byte(rr.Permissions.String), &role.Permissions)
        }
        out = append(out, role)
    }
    return out, nil
}

// Update updates mutable fields of a role.
func (r *roleRepository) Update(ctx context.Context, role *Role) error {
    role.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

    permsJSON, err := json.Marshal(role.Permissions)
    if err != nil {
        return fmt.Errorf("marshal permissions: %w", err)
    }

    query := `
UPDATE roles SET
  name = :name,
  description = :description,
  permissions = :permissions,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":          role.ID,
        "name":        role.Name,
        "description": role.Description,
        "permissions": string(permsJSON),
        "updated_at":  role.UpdatedAt,
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
        return fmt.Errorf("role not found")
    }
    return nil
}

// Delete removes a role record.
func (r *roleRepository) Delete(ctx context.Context, id string) error {
    res, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("role not found")
    }
    return nil
}
