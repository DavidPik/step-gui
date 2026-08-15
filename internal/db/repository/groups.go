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

// Group represents a logical grouping of users or devices used for scoping approvals and delegation.
type Group struct {
    ID             string  `db:"id"`
    Name           string  `db:"name"`
    Type           string  `db:"type"` // "user" or "device"
    ApproverRoleID *string `db:"approver_role_id"` // optional mapping to a role record (nullable)
    Description    *string `db:"description"`
    CreatedAt      string  `db:"created_at"`
    UpdatedAt      string  `db:"updated_at"`
}

// GroupRepository defines persistence operations for groups and helper queries used by RBAC/approval logic.
type GroupRepository interface {
    Create(ctx context.Context, g *Group) error
    GetByID(ctx context.Context, id string) (*Group, error)
    GetByName(ctx context.Context, name string) (*Group, error)
    List(ctx context.Context) ([]Group, error)
    Update(ctx context.Context, g *Group) error
    Delete(ctx context.Context, id string) error

    // Helpers for approver/ delegation logic
    // ListApproversForGroup returns users who have the Approver role and are members of the group.
    ListApproversForGroup(ctx context.Context, groupID string) ([]User, error)
    // IsUserApproverForGroup checks whether a given user is an approver for the specified group.
    IsUserApproverForGroup(ctx context.Context, userID string, groupID string) (bool, error)
}

type groupRepository struct {
    db *sqlx.DB
}

// NewGroupRepository constructs a MariaDB-backed GroupRepository.
func NewGroupRepository(db *sqlx.DB) GroupRepository {
    return &groupRepository{db: db}
}

// Create inserts a new group record.
func (r *groupRepository) Create(ctx context.Context, g *Group) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if g.CreatedAt == "" {
        g.CreatedAt = now
    }
    g.UpdatedAt = now

    query := `
INSERT INTO groups
(id, name, type, approver_role_id, description, created_at, updated_at)
VALUES
(:id, :name, :type, :approver_role_id, :description, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":               g.ID,
        "name":             g.Name,
        "type":             g.Type,
        "approver_role_id": g.ApproverRoleID,
        "description":      g.Description,
        "created_at":       g.CreatedAt,
        "updated_at":       g.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a group by id.
func (r *groupRepository) GetByID(ctx context.Context, id string) (*Group, error) {
    var g Group
    query := `SELECT id, name, type, approver_role_id, description, created_at, updated_at FROM groups WHERE id = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &g, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("group not found")
        }
        return nil, err
    }
    return &g, nil
}

// GetByName returns a group by name.
func (r *groupRepository) GetByName(ctx context.Context, name string) (*Group, error) {
    var g Group
    query := `SELECT id, name, type, approver_role_id, description, created_at, updated_at FROM groups WHERE name = ? LIMIT 1`
    if err := r.db.GetContext(ctx, &g, query, name); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("group not found")
        }
        return nil, err
    }
    return &g, nil
}

// List returns all groups.
func (r *groupRepository) List(ctx context.Context) ([]Group, error) {
    var groups []Group
    query := `SELECT id, name, type, approver_role_id, description, created_at, updated_at FROM groups ORDER BY name ASC LIMIT 1000`
    if err := r.db.SelectContext(ctx, &groups, query); err != nil {
        return nil, err
    }
    return groups, nil
}

// Update updates mutable fields of a group.
func (r *groupRepository) Update(ctx context.Context, g *Group) error {
    g.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    query := `
UPDATE groups SET
  name = :name,
  type = :type,
  approver_role_id = :approver_role_id,
  description = :description,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":               g.ID,
        "name":             g.Name,
        "type":             g.Type,
        "approver_role_id": g.ApproverRoleID,
        "description":      g.Description,
        "updated_at":       g.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// Delete removes a group record.
func (r *groupRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
    return err
}

//
// Approver / delegation helpers
//

// ListApproversForGroup returns users who have the Approver role and are members of the group.
// It expects users.roles to be stored as JSON array and users.groups as JSON array (MariaDB JSON).
func (r *groupRepository) ListApproversForGroup(ctx context.Context, groupID string) ([]User, error) {
    // Query users where JSON_CONTAINS(roles, '"Approver"') AND JSON_CONTAINS(groups, '"groupID"')
    query := `
SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at
FROM users
WHERE JSON_CONTAINS(roles, '\"Approver\"')
  AND JSON_CONTAINS(groups, '\"` + groupID + `\"')
ORDER BY username ASC
LIMIT 1000
`
    rows := []struct {
        ID          string         `db:"id"`
        Username    string         `db:"username"`
        DisplayName string         `db:"display_name"`
        Email       string         `db:"email"`
        Roles       sql.NullString `db:"roles"`
        Groups      sql.NullString `db:"groups"`
        Status      string         `db:"status"`
        AuthSource  string         `db:"auth_source"`
        MFAConfig   *string        `db:"mfa_config"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }{}

    if err := r.db.SelectContext(ctx, &rows, query); err != nil {
        return nil, err
    }

    users := make([]User, 0, len(rows))
    for _, rr := range rows {
        u := User{
            ID:          rr.ID,
            Username:    rr.Username,
            DisplayName: rr.DisplayName,
            Email:       rr.Email,
            Status:      rr.Status,
            AuthSource:  rr.AuthSource,
            MFAConfig:   rr.MFAConfig,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
        }
        if rr.Roles.Valid {
            _ = json.Unmarshal([]byte(rr.Roles.String), &u.Roles)
        }
        if rr.Groups.Valid {
            _ = json.Unmarshal([]byte(rr.Groups.String), &u.Groups)
        }
        users = append(users, u)
    }
    return users, nil
}

// IsUserApproverForGroup checks whether a given user is an approver for the specified group.
func (r *groupRepository) IsUserApproverForGroup(ctx context.Context, userID string, groupID string) (bool, error) {
    query := `
SELECT 1 FROM users
WHERE id = ?
  AND JSON_CONTAINS(roles, '\"Approver\"')
  AND JSON_CONTAINS(groups, '\"` + groupID + `\"')
LIMIT 1
`
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, userID)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

//
// Utility helpers
//

// buildJSONContainsOrClause builds an OR clause that checks JSON_CONTAINS(field, '"id"') for each id.
// This helper is reused by other repositories; keep it here for convenience.
func buildJSONContainsOrClause(jsonField string, ids []string) string {
    parts := make([]string, 0, len(ids))
    for _, id := range ids {
        parts = append(parts, fmt.Sprintf("JSON_CONTAINS(%s, '\"%s\"')", jsonField, id))
    }
    return "(" + strings.Join(parts, " OR ") + ")"
}
