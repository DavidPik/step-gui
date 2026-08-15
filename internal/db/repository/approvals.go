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

// Approval represents an approval workflow record.
type Approval struct {
    ID          string  `db:"id"`
    RequesterID string  `db:"requester_id"`
    TargetType  string  `db:"target_type"` // user|device|certificate
    TargetID    *string `db:"target_id"`
    PolicyID    *string `db:"policy_id"`
    ApproverID  *string `db:"approver_id"`
    Status      string  `db:"status"` // pending|approved|rejected|error
    RequestedAt string  `db:"requested_at"`
    DecidedAt   *string `db:"decided_at"`
    Reason      *string `db:"reason"`
    Payload     *string `db:"payload"` // JSON payload (CSR, metadata, etc.)
    CreatedAt   string  `db:"created_at"`
    UpdatedAt   string  `db:"updated_at"`
}

// ApprovalRepository defines persistence operations for approvals and helper queries
// used by API handlers and worker processes.
type ApprovalRepository interface {
    Create(ctx context.Context, a *Approval) error
    GetByID(ctx context.Context, id string) (*Approval, error)
    ListPending(ctx context.Context, limit int) ([]Approval, error)
    // ListPendingForApprover returns pending approvals that the approver is eligible to act on.
    // Eligibility is determined by approver's group membership (groupIDs) and optional global approver flag.
    ListPendingForApprover(ctx context.Context, approverID string, groupIDs []string, limit int) ([]Approval, error)
    // ListForRequester returns approvals created by a requester (for Viewer scoping).
    ListForRequester(ctx context.Context, requesterID string) ([]Approval, error)
    UpdateStatus(ctx context.Context, id string, status string, approverID *string, reason *string) error
    Delete(ctx context.Context, id string) error

    // Helper: CountPendingForGroups returns number of pending approvals for given groups (used for dashboards/alerts).
    CountPendingForGroups(ctx context.Context, groupIDs []string) (int, error)
}

type approvalRepository struct {
    db *sqlx.DB
}

// NewApprovalRepository constructs a MariaDB-backed ApprovalRepository.
func NewApprovalRepository(db *sqlx.DB) ApprovalRepository {
    return &approvalRepository{db: db}
}

// Create inserts a new approval record.
func (r *approvalRepository) Create(ctx context.Context, a *Approval) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if a.CreatedAt == "" {
        a.CreatedAt = now
    }
    a.UpdatedAt = now
    if a.RequestedAt == "" {
        a.RequestedAt = now
    }
    query := `
INSERT INTO approvals
(id, requester_id, target_type, target_id, policy_id, approver_id, status, requested_at, decided_at, reason, payload, created_at, updated_at)
VALUES
(:id, :requester_id, :target_type, :target_id, :policy_id, :approver_id, :status, :requested_at, :decided_at, :reason, :payload, :created_at, :updated_at)
`
    params := map[string]interface{}{
        "id":           a.ID,
        "requester_id": a.RequesterID,
        "target_type":  a.TargetType,
        "target_id":    a.TargetID,
        "policy_id":    a.PolicyID,
        "approver_id":  a.ApproverID,
        "status":       a.Status,
        "requested_at": a.RequestedAt,
        "decided_at":   a.DecidedAt,
        "reason":       a.Reason,
        "payload":      a.Payload,
        "created_at":   a.CreatedAt,
        "updated_at":   a.UpdatedAt,
    }
    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// GetByID returns an approval by id.
func (r *approvalRepository) GetByID(ctx context.Context, id string) (*Approval, error) {
    var a Approval
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status,
       requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE id = ? LIMIT 1
`
    if err := r.db.GetContext(ctx, &a, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("approval not found")
        }
        return nil, err
    }
    return &a, nil
}

// ListPending returns recent pending approvals (global).
func (r *approvalRepository) ListPending(ctx context.Context, limit int) ([]Approval, error) {
    if limit <= 0 {
        limit = 200
    }
    var list []Approval
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status,
       requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE status = 'pending'
ORDER BY requested_at ASC
LIMIT ?
`
    if err := r.db.SelectContext(ctx, &list, query, limit); err != nil {
        return nil, err
    }
    return list, nil
}

// ListPendingForApprover returns pending approvals that the approver can act on.
// The repository uses groupIDs to filter approvals whose target (device/user) belongs to those groups.
// For certificate targets, it checks the related device/user group via joins.
// This function assumes groups are stored on devices (devices.group_id) and users (users.groups JSON).
func (r *approvalRepository) ListPendingForApprover(ctx context.Context, approverID string, groupIDs []string, limit int) ([]Approval, error) {
    if limit <= 0 {
        limit = 200
    }
    // If no groups provided, return global pending approvals (approver may be global).
    if len(groupIDs) == 0 {
        return r.ListPending(ctx, limit)
    }

    // Build placeholders for IN clause
    placeholders := strings.Repeat("?,", len(groupIDs))
    placeholders = strings.TrimRight(placeholders, ",")

    // Build JSON_CONTAINS OR clause for users.groups
    jsonClause := buildJSONContainsOrClause("u.groups", groupIDs)

    // Query pending approvals where:
    // - target_type = 'certificate' and certificate.owner_device_id -> device.group_id IN (...)
    // - OR target_type = 'device' and device.group_id IN (...)
    // - OR target_type = 'user' and user.groups contains group
    // - OR approvals without target (fallback) are included if approver is global (handled by caller)
    query := fmt.Sprintf(`
SELECT DISTINCT a.id, a.requester_id, a.target_type, a.target_id, a.policy_id, a.approver_id, a.status,
       a.requested_at, a.decided_at, a.reason, a.payload, a.created_at, a.updated_at
FROM approvals a
LEFT JOIN certificates c ON a.target_type = 'certificate' AND a.target_id = c.id
LEFT JOIN devices d ON (a.target_type = 'device' AND a.target_id = d.id) OR (c.owner_device_id = d.id)
LEFT JOIN users u ON (a.target_type = 'user' AND a.target_id = u.id) OR (c.owner_user_id = u.id)
WHERE a.status = 'pending'
  AND (
       (d.group_id IN (%s))
    OR (%s)
  )
ORDER BY a.requested_at ASC
LIMIT ?
`, placeholders, jsonClause)

    // Build args for IN clause
    args := make([]interface{}, 0, len(groupIDs)+1)
    for _, g := range groupIDs {
        args = append(args, g)
    }
    args = append(args, limit)

    var list []Approval
    if err := r.db.SelectContext(ctx, &list, query, args...); err != nil {
        return nil, err
    }
    return list, nil
}

// ListForRequester returns approvals created by a requester (used for Viewer scoping).
func (r *approvalRepository) ListForRequester(ctx context.Context, requesterID string) ([]Approval, error) {
    var list []Approval
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status,
       requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE requester_id = ?
ORDER BY requested_at DESC
LIMIT 1000
`
    if err := r.db.SelectContext(ctx, &list, query, requesterID); err != nil {
        return nil, err
    }
    return list, nil
}

// UpdateStatus updates approval status and records approver and reason.
func (r *approvalRepository) UpdateStatus(ctx context.Context, id string, status string, approverID *string, reason *string) error {
    now := time.Now().UTC().Format(time.RFC3339)
    query := `
UPDATE approvals SET
  status = :status,
  approver_id = :approver_id,
  reason = :reason,
  decided_at = :decided_at,
  updated_at = :updated_at
WHERE id = :id
`
    params := map[string]interface{}{
        "id":          id,
        "status":      status,
        "approver_id": approverID,
        "reason":      reason,
        "decided_at":  now,
        "updated_at":  now,
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
        return fmt.Errorf("approval not found")
    }
    return nil
}

// Delete removes an approval record.
func (r *approvalRepository) Delete(ctx context.Context, id string) error {
    _, err := r.db.ExecContext(ctx, `DELETE FROM approvals WHERE id = ?`, id)
    return err
}

// CountPendingForGroups returns the number of pending approvals for the provided groups.
func (r *approvalRepository) CountPendingForGroups(ctx context.Context, groupIDs []string) (int, error) {
    if len(groupIDs) == 0 {
        // count all pending
        var cnt int
        if err := r.db.GetContext(ctx, &cnt, `SELECT COUNT(1) FROM approvals WHERE status = 'pending'`); err != nil {
            return 0, err
        }
        return cnt, nil
    }
    placeholders := strings.Repeat("?,", len(groupIDs))
    placeholders = strings.TrimRight(placeholders, ",")

    jsonClause := buildJSONContainsOrClause("u.groups", groupIDs)

    query := fmt.Sprintf(`
SELECT COUNT(DISTINCT a.id) FROM approvals a
LEFT JOIN certificates c ON a.target_type = 'certificate' AND a.target_id = c.id
LEFT JOIN devices d ON (a.target_type = 'device' AND a.target_id = d.id) OR (c.owner_device_id = d.id)
LEFT JOIN users u ON (a.target_type = 'user' AND a.target_id = u.id) OR (c.owner_user_id = u.id)
WHERE a.status = 'pending'
  AND (d.group_id IN (%s) OR %s)
`, placeholders, jsonClause)

    args := make([]interface{}, 0, len(groupIDs))
    for _, g := range groupIDs {
        args = append(args, g)
    }

    var cnt int
    if err := r.db.GetContext(ctx, &cnt, query, args...); err != nil {
        return 0, err
    }
    return cnt, nil
}

//
// Helper utilities
//

// buildJSONContainsOrClause builds an OR clause that checks JSON_CONTAINS(field, '"id"') for each id.
// Example output: (JSON_CONTAINS(u.groups, '"g1"') OR JSON_CONTAINS(u.groups, '"g2"'))
func buildJSONContainsOrClause(jsonField string, ids []string) string {
    parts := make([]string, 0, len(ids))
    for _, id := range ids {
        // JSON_CONTAINS(field, '"id"') checks if the string exists in the JSON array.
        parts = append(parts, fmt.Sprintf("JSON_CONTAINS(%s, '\"%s\"')", jsonField, id))
    }
    return "(" + strings.Join(parts, " OR ") + ")"
}

// Utility to marshal a payload (map or struct) into JSON string pointer.
func MarshalPayload(v any) (*string, error) {
    if v == nil {
        return nil, nil
    }
    b, err := json.Marshal(v)
    if err != nil {
        return nil, err
    }
    s := string(b)
    return &s, nil
}
