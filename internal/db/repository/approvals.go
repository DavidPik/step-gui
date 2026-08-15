package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// Approval represents an approval/request record.
type Approval struct {
    ID          string  `db:"id"`
    RequesterID string  `db:"requester_id"`
    TargetType  string  `db:"target_type"`
    TargetID    *string `db:"target_id"`
    PolicyID    *string `db:"policy_id"`
    ApproverID  *string `db:"approver_id"`
    Status      string  `db:"status"` // pending|approved|rejected|error
    RequestedAt string  `db:"requested_at"`
    DecidedAt   *string `db:"decided_at"`
    Reason      *string `db:"reason"`
    Payload     string  `db:"payload"` // JSON string
    CreatedAt   string  `db:"created_at"`
    UpdatedAt   string  `db:"updated_at"`
}

// ApprovalRepository defines persistence operations for approvals.
type ApprovalRepository interface {
    Create(ctx context.Context, a *Approval) error
    GetByID(ctx context.Context, id string) (*Approval, error)
    ListByStatus(ctx context.Context, status string, limit int) ([]Approval, error)
    ListPending(ctx context.Context, limit int) ([]Approval, error)
    ListByRequester(ctx context.Context, requesterID string, limit int) ([]Approval, error)
    UpdateStatus(ctx context.Context, id string, status string, approverID *string, reason *string) error
    Delete(ctx context.Context, id string) error
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
    if a.RequestedAt == "" {
        a.RequestedAt = now
    }
    a.UpdatedAt = now
    if a.Status == "" {
        a.Status = "pending"
    }
    // Ensure payload is valid JSON (or at least a JSON string)
    if a.Payload == "" {
        a.Payload = "{}"
    } else {
        var tmp interface{}
        if err := json.Unmarshal([]byte(a.Payload), &tmp); err != nil {
            // If not valid JSON, marshal as string
            b, _ := json.Marshal(a.Payload)
            a.Payload = string(b)
        }
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
    var row struct {
        ID          string         `db:"id"`
        RequesterID string         `db:"requester_id"`
        TargetType  string         `db:"target_type"`
        TargetID    sql.NullString `db:"target_id"`
        PolicyID    sql.NullString `db:"policy_id"`
        ApproverID  sql.NullString `db:"approver_id"`
        Status      string         `db:"status"`
        RequestedAt string         `db:"requested_at"`
        DecidedAt   sql.NullString `db:"decided_at"`
        Reason      sql.NullString `db:"reason"`
        Payload     sql.NullString `db:"payload"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status, requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE id = ? LIMIT 1
`
    if err := r.db.GetContext(ctx, &row, query, id); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("approval not found")
        }
        return nil, err
    }
    a := &Approval{
        ID:          row.ID,
        RequesterID: row.RequesterID,
        TargetType:  row.TargetType,
        Status:      row.Status,
        RequestedAt: row.RequestedAt,
        CreatedAt:   row.CreatedAt,
        UpdatedAt:   row.UpdatedAt,
        Payload:     "{}",
    }
    if row.TargetID.Valid {
        v := row.TargetID.String
        a.TargetID = &v
    }
    if row.PolicyID.Valid {
        v := row.PolicyID.String
        a.PolicyID = &v
    }
    if row.ApproverID.Valid {
        v := row.ApproverID.String
        a.ApproverID = &v
    }
    if row.DecidedAt.Valid {
        v := row.DecidedAt.String
        a.DecidedAt = &v
    }
    if row.Reason.Valid {
        v := row.Reason.String
        a.Reason = &v
    }
    if row.Payload.Valid {
        a.Payload = row.Payload.String
    }
    return a, nil
}

// ListByStatus returns approvals filtered by status.
func (r *approvalRepository) ListByStatus(ctx context.Context, status string, limit int) ([]Approval, error) {
    if limit <= 0 {
        limit = 200
    }
    var rows []struct {
        ID          string         `db:"id"`
        RequesterID string         `db:"requester_id"`
        TargetType  string         `db:"target_type"`
        TargetID    sql.NullString `db:"target_id"`
        PolicyID    sql.NullString `db:"policy_id"`
        ApproverID  sql.NullString `db:"approver_id"`
        Status      string         `db:"status"`
        RequestedAt string         `db:"requested_at"`
        DecidedAt   sql.NullString `db:"decided_at"`
        Reason      sql.NullString `db:"reason"`
        Payload     sql.NullString `db:"payload"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status, requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE status = ?
ORDER BY requested_at ASC
LIMIT ?
`
    if err := r.db.SelectContext(ctx, &rows, query, status, limit); err != nil {
        return nil, err
    }
    out := make([]Approval, 0, len(rows))
    for _, rr := range rows {
        a := Approval{
            ID:          rr.ID,
            RequesterID: rr.RequesterID,
            TargetType:  rr.TargetType,
            Status:      rr.Status,
            RequestedAt: rr.RequestedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            Payload:     "{}",
        }
        if rr.TargetID.Valid {
            v := rr.TargetID.String
            a.TargetID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            a.PolicyID = &v
        }
        if rr.ApproverID.Valid {
            v := rr.ApproverID.String
            a.ApproverID = &v
        }
        if rr.DecidedAt.Valid {
            v := rr.DecidedAt.String
            a.DecidedAt = &v
        }
        if rr.Reason.Valid {
            v := rr.Reason.String
            a.Reason = &v
        }
        if rr.Payload.Valid {
            a.Payload = rr.Payload.String
        }
        out = append(out, a)
    }
    return out, nil
}

// ListPending is a convenience wrapper for ListByStatus("pending", limit).
func (r *approvalRepository) ListPending(ctx context.Context, limit int) ([]Approval, error) {
    return r.ListByStatus(ctx, "pending", limit)
}

// ListByRequester returns approvals created by a requester.
func (r *approvalRepository) ListByRequester(ctx context.Context, requesterID string, limit int) ([]Approval, error) {
    if limit <= 0 {
        limit = 200
    }
    var rows []struct {
        ID          string         `db:"id"`
        RequesterID string         `db:"requester_id"`
        TargetType  string         `db:"target_type"`
        TargetID    sql.NullString `db:"target_id"`
        PolicyID    sql.NullString `db:"policy_id"`
        ApproverID  sql.NullString `db:"approver_id"`
        Status      string         `db:"status"`
        RequestedAt string         `db:"requested_at"`
        DecidedAt   sql.NullString `db:"decided_at"`
        Reason      sql.NullString `db:"reason"`
        Payload     sql.NullString `db:"payload"`
        CreatedAt   string         `db:"created_at"`
        UpdatedAt   string         `db:"updated_at"`
    }
    query := `
SELECT id, requester_id, target_type, target_id, policy_id, approver_id, status, requested_at, decided_at, reason, payload, created_at, updated_at
FROM approvals
WHERE requester_id = ?
ORDER BY requested_at DESC
LIMIT ?
`
    if err := r.db.SelectContext(ctx, &rows, query, requesterID, limit); err != nil {
        return nil, err
    }
    out := make([]Approval, 0, len(rows))
    for _, rr := range rows {
        a := Approval{
            ID:          rr.ID,
            RequesterID: rr.RequesterID,
            TargetType:  rr.TargetType,
            Status:      rr.Status,
            RequestedAt: rr.RequestedAt,
            CreatedAt:   rr.CreatedAt,
            UpdatedAt:   rr.UpdatedAt,
            Payload:     "{}",
        }
        if rr.TargetID.Valid {
            v := rr.TargetID.String
            a.TargetID = &v
        }
        if rr.PolicyID.Valid {
            v := rr.PolicyID.String
            a.PolicyID = &v
        }
        if rr.ApproverID.Valid {
            v := rr.ApproverID.String
            a.ApproverID = &v
        }
        if rr.DecidedAt.Valid {
            v := rr.DecidedAt.String
            a.DecidedAt = &v
        }
        if rr.Reason.Valid {
            v := rr.Reason.String
            a.Reason = &v
        }
        if rr.Payload.Valid {
            a.Payload = rr.Payload.String
        }
        out = append(out, a)
    }
    return out, nil
}

// UpdateStatus updates the status of an approval and records approver, reason and decided_at.
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
    res, err := r.db.ExecContext(ctx, `DELETE FROM approvals WHERE id = ?`, id)
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
