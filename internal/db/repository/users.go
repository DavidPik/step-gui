package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// User represents a user record stored in MariaDB.
// Note: roles and groups are stored as JSON arrays in the DB (MariaDB JSON type).
type User struct {
    ID          string   `db:"id"`
    Username    string   `db:"username"`
    DisplayName string   `db:"display_name"`
    Email       string   `db:"email"`
    Roles       []string `db:"roles"`  // JSON array in DB
    Groups      []string `db:"groups"` // JSON array in DB
    Status      string   `db:"status"`
    AuthSource  string   `db:"auth_source"`
    MFAConfig   *string  `db:"mfa_config"`
    CreatedAt   string   `db:"created_at"`
    UpdatedAt   string   `db:"updated_at"`
}

// UserRepository defines persistence operations used by the API.
type UserRepository interface {
    Create(ctx context.Context, u *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    GetByUsername(ctx context.Context, username string) (*User, error)
    List(ctx context.Context) ([]User, error)
    Update(ctx context.Context, u *User) error
    Delete(ctx context.Context, id string) error

    // Helpers used by RBAC and scoping logic
    GetRoles(ctx context.Context, userID string) ([]string, error)
    GetGroups(ctx context.Context, userID string) ([]string, error)
    IsInGroup(ctx context.Context, userID string, groupID string) (bool, error)

    // Additional helpers
    IsInRole(ctx context.Context, userID string, roleName string) (bool, error)
    ListByGroup(ctx context.Context, groupID string) ([]User, error)
    ListApproversForGroup(ctx context.Context, groupID string) ([]User, error)

    // RedactForAPI returns a copy of the user safe for returning to clients (removes sensitive fields).
    RedactForAPI(u *User) *User
}

type userRepository struct {
    db *sqlx.DB
}

// NewUserRepository constructs a MariaDB-backed UserRepository.
func NewUserRepository(db *sqlx.DB) UserRepository {
    return &userRepository{db: db}
}

// Create inserts a new user record. Expects u.Roles and u.Groups to be set (or empty slices).
func (r *userRepository) Create(ctx context.Context, u *User) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if u.CreatedAt == "" {
        u.CreatedAt = now
    }
    u.UpdatedAt = now

    rolesJSON, _ := json.Marshal(u.Roles)
    groupsJSON, _ := json.Marshal(u.Groups)

    query := `
INSERT INTO users
(id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at)
VALUES
(:id, :username, :display_name, :email, :roles, :groups, :status, :auth_source, :mfa_config, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":           u.ID,
        "username":     u.Username,
        "display_name": u.DisplayName,
        "email":        u.Email,
        "roles":        string(rolesJSON),
        "groups":       string(groupsJSON),
        "status":       u.Status,
        "auth_source":  u.AuthSource,
        "mfa_config":   u.MFAConfig,
        "created_at":   u.CreatedAt,
        "updated_at":   u.UpdatedAt,
    }

    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns a user by id.
func (r *userRepository) GetByID(ctx context.Context, id string) (*User, error) {
    var u User
    query := `SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at FROM users WHERE id = ? LIMIT 1`
    var rolesRaw sql.NullString
    var groupsRaw sql.NullString

    row := r.db.QueryRowxContext(ctx, query, id)
    if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &rolesRaw, &groupsRaw, &u.Status, &u.AuthSource, &u.MFAConfig, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, err
    }

    // parse JSON fields
    if rolesRaw.Valid {
        _ = json.Unmarshal([]byte(rolesRaw.String), &u.Roles)
    }
    if groupsRaw.Valid {
        _ = json.Unmarshal([]byte(groupsRaw.String), &u.Groups)
    }

    return &u, nil
}

// GetByUsername returns a user by username.
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
    var u User
    query := `SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at FROM users WHERE username = ? LIMIT 1`
    var rolesRaw sql.NullString
    var groupsRaw sql.NullString

    row := r.db.QueryRowxContext(ctx, query, username)
    if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &rolesRaw, &groupsRaw, &u.Status, &u.AuthSource, &u.MFAConfig, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, err
    }

    if rolesRaw.Valid {
        _ = json.Unmarshal([]byte(rolesRaw.String), &u.Roles)
    }
    if groupsRaw.Valid {
        _ = json.Unmarshal([]byte(groupsRaw.String), &u.Groups)
    }

    return &u, nil
}

// List returns all users. Caller must enforce RBAC (e.g., Admin only).
func (r *userRepository) List(ctx context.Context) ([]User, error) {
    var rows []struct {
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
    }
    query := `SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at FROM users ORDER BY username ASC LIMIT 1000`
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

// Update updates mutable fields of a user. Caller must enforce RBAC.
func (r *userRepository) Update(ctx context.Context, u *User) error {
    u.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    rolesJSON, _ := json.Marshal(u.Roles)
    groupsJSON, _ := json.Marshal(u.Groups)

    query := `
UPDATE users SET
  username = :username,
  display_name = :display_name,
  email = :email,
  roles = :roles,
  groups = :groups,
  status = :status,
  auth_source = :auth_source,
  mfa_config = :mfa_config,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":           u.ID,
        "username":     u.Username,
        "display_name": u.DisplayName,
        "email":        u.Email,
        "roles":        string(rolesJSON),
        "groups":       string(groupsJSON),
        "status":       u.Status,
        "auth_source":  u.AuthSource,
        "mfa_config":   u.MFAConfig,
        "updated_at":   u.UpdatedAt,
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
        return fmt.Errorf("user not found")
    }
    return nil
}

// Delete removes a user record.
func (r *userRepository) Delete(ctx context.Context, id string) error {
    res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
    if err != nil {
        return err
    }
    ra, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if ra == 0 {
        return fmt.Errorf("user not found")
    }
    return nil
}

//
// Helper methods for RBAC and scoping
//

// GetRoles returns the roles assigned to a user.
func (r *userRepository) GetRoles(ctx context.Context, userID string) ([]string, error) {
    u, err := r.GetByID(ctx, userID)
    if err != nil {
        return nil, err
    }
    return u.Roles, nil
}

// GetGroups returns group IDs the user belongs to.
func (r *userRepository) GetGroups(ctx context.Context, userID string) ([]string, error) {
    u, err := r.GetByID(ctx, userID)
    if err != nil {
        return nil, err
    }
    return u.Groups, nil
}

// IsInGroup checks whether the user is a member of the given group.
func (r *userRepository) IsInGroup(ctx context.Context, userID string, groupID string) (bool, error) {
    // Use JSON_CONTAINS to avoid loading full user record.
    // JSON_CONTAINS(groups, '"groupID"')
    query := `SELECT 1 FROM users WHERE id = ? AND JSON_CONTAINS(groups, ?) LIMIT 1`
    needle := fmt.Sprintf(`"%s"`, groupID)
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, userID, needle)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

// IsInRole checks whether the user has a given role name.
func (r *userRepository) IsInRole(ctx context.Context, userID string, roleName string) (bool, error) {
    // JSON_CONTAINS(roles, '"roleName"')
    query := `SELECT 1 FROM users WHERE id = ? AND JSON_CONTAINS(roles, ?) LIMIT 1`
    needle := fmt.Sprintf(`"%s"`, roleName)
    var dummy int
    err := r.db.GetContext(ctx, &dummy, query, userID, needle)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, err
    }
    return true, nil
}

// ListByGroup returns users that belong to a specific group.
func (r *userRepository) ListByGroup(ctx context.Context, groupID string) ([]User, error) {
    var rows []struct {
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
    }
    query := `SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at FROM users WHERE JSON_CONTAINS(groups, ?) ORDER BY username ASC LIMIT 1000`
    needle := fmt.Sprintf(`"%s"`, groupID)
    if err := r.db.SelectContext(ctx, &rows, query, needle); err != nil {
        return nil, err
    }

    out := make([]User, 0, len(rows))
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
        out = append(out, u)
    }
    return out, nil
}

// ListApproversForGroup returns users who are approvers for the given group.
// Logic:
// 1. Try to read groups.approver_role_id. If set, resolve that role id to a role name and find users whose roles JSON contains that role name and who are members of the group.
// 2. If approver_role_id is not set or role lookup fails, fall back to users with role name "approver" who are members of the group.
func (r *userRepository) ListApproversForGroup(ctx context.Context, groupID string) ([]User, error) {
    // Step 1: get approver_role_id from groups
    var approverRoleID sql.NullString
    if err := r.db.GetContext(ctx, &approverRoleID, `SELECT approver_role_id FROM groups WHERE id = ? LIMIT 1`, groupID); err != nil {
        if err == sql.ErrNoRows {
            // No such group -> empty list
            return nil, nil
        }
        return nil, err
    }

    roleName := ""
    if approverRoleID.Valid && approverRoleID.String != "" {
        // Resolve role name
        var rn sql.NullString
        if err := r.db.GetContext(ctx, &rn, `SELECT name FROM roles WHERE id = ? LIMIT 1`, approverRoleID.String); err != nil {
            // If role lookup fails, we'll fall back to default below
            roleName = ""
        } else if rn.Valid {
            roleName = rn.String
        }
    }

    if roleName == "" {
        // fallback to literal role name "approver"
        roleName = "approver"
    }

    needleRole := fmt.Sprintf(`"%s"`, roleName)
    needleGroup := fmt.Sprintf(`"%s"`, groupID)

    var rows []struct {
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
    }

    query := `SELECT id, username, display_name, email, roles, groups, status, auth_source, mfa_config, created_at, updated_at FROM users WHERE JSON_CONTAINS(roles, ?) AND JSON_CONTAINS(groups, ?) ORDER BY username ASC LIMIT 1000`
    if err := r.db.SelectContext(ctx, &rows, query, needleRole, needleGroup); err != nil {
        return nil, err
    }

    out := make([]User, 0, len(rows))
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
        out = append(out, u)
    }
    return out, nil
}

// RedactForAPI returns a copy of the user safe for returning to clients (removes sensitive fields).
func (r *userRepository) RedactForAPI(u *User) *User {
    if u == nil {
        return nil
    }
    redacted := *u
    // Remove MFA config from API responses
    redacted.MFAConfig = nil
    // Mask email local part but keep domain for usability
    if redacted.Email != "" {
        // simple mask: keep domain, replace local part with first char + ****
        at := -1
        for i := len(redacted.Email) - 1; i >= 0; i-- {
            if redacted.Email[i] == '@' {
                at = i
                break
            }
        }
        if at > 1 {
            local := redacted.Email[:at]
            domain := redacted.Email[at:]
            if len(local) > 1 {
                redacted.Email = local[:1] + "****" + domain
            } else {
                redacted.Email = "****" + domain
            }
        }
    }
    return &redacted
}
