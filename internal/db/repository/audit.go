package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/jmoiron/sqlx"
)

// AuditLog represents an append-only audit record.
type AuditLog struct {
    ID                string  `db:"id"`
    Timestamp         string  `db:"timestamp"`
    UserID            *string `db:"user_id"`
    Action            string  `db:"action"`
    ObjectType        string  `db:"object_type"`
    ObjectID          *string `db:"object_id"`
    Details           string  `db:"details"` // JSON string
    SentToSyslog      int     `db:"sent_to_syslog"`
    SyslogLastAttempt *string `db:"syslog_last_attempt"`
    SyslogStatus      *string `db:"syslog_status"`
}

// AuditRepository defines append-only audit operations.
// Reads are intended to be restricted to Admins by the API layer.
type AuditRepository interface {
    // Create appends a new audit record. Details should be a JSON-serializable value or a JSON string.
    Create(ctx context.Context, a *AuditLog) error

    // List returns recent audit records ordered by timestamp descending.
    // Caller should enforce Admin-only access.
    List(ctx context.Context, limit int) ([]AuditLog, error)
}

type auditRepository struct {
    db *sqlx.DB
}

// NewAuditRepository constructs a MariaDB-backed AuditRepository.
func NewAuditRepository(db *sqlx.DB) AuditRepository {
    return &auditRepository{db: db}
}

// Create inserts a new audit record. The repository ensures timestamp and defaults are set.
// Details may be provided as a JSON string or as an arbitrary value (will be marshaled).
func (r *auditRepository) Create(ctx context.Context, a *AuditLog) error {
    now := time.Now().UTC().Format(time.RFC3339)
    if a.Timestamp == "" {
        a.Timestamp = now
    }
    // Ensure defaults
    if a.SentToSyslog != 1 {
        a.SentToSyslog = 0
    }

    // If Details looks like a JSON object (not strictly enforced), keep it.
    // If it's not JSON, attempt to marshal it as a string wrapper.
    if a.Details == "" {
        a.Details = "{}"
    } else {
        // Validate JSON; if invalid, marshal as string
        var tmp interface{}
        if err := json.Unmarshal([]byte(a.Details), &tmp); err != nil {
            // Not valid JSON — marshal as JSON string
            b, _ := json.Marshal(a.Details)
            a.Details = string(b)
        }
    }

    // Use named exec for clarity. The DB schema should have id as CHAR(36) or BIGINT depending on migration.
    query := `
INSERT INTO audit_logs
(id, actor_id, action, target_type, target_id, details, timestamp, sent_to_syslog, syslog_last_attempt, syslog_status)
VALUES
(:id, :actor_id, :action, :target_type, :target_id, :details, :timestamp, :sent_to_syslog, :syslog_last_attempt, :syslog_status)
`
    params := map[string]interface{}{
        "id":                 a.ID,
        "actor_id":           a.UserID,
        "action":             a.Action,
        "target_type":        a.ObjectType,
        "target_id":          a.ObjectID,
        "details":            a.Details,
        "timestamp":          a.Timestamp,
        "sent_to_syslog":     a.SentToSyslog,
        "syslog_last_attempt": a.SyslogLastAttempt,
        "syslog_status":      a.SyslogStatus,
    }

    _, err := r.db.NamedExecContext(ctx, query, params)
    return err
}

// List returns recent audit records. Caller must enforce Admin-only access.
func (r *auditRepository) List(ctx context.Context, limit int) ([]AuditLog, error) {
    if limit <= 0 {
        limit = 200
    }
    var rows []struct {
        ID                sql.NullString `db:"id"`
        Timestamp         sql.NullString `db:"timestamp"`
        ActorID           sql.NullString `db:"actor_id"`
        Action            sql.NullString `db:"action"`
        TargetType        sql.NullString `db:"target_type"`
        TargetID          sql.NullString `db:"target_id"`
        Details           sql.NullString `db:"details"`
        SentToSyslog      sql.NullInt64  `db:"sent_to_syslog"`
        SyslogLastAttempt sql.NullString `db:"syslog_last_attempt"`
        SyslogStatus      sql.NullString `db:"syslog_status"`
    }

    query := `
SELECT id, timestamp, actor_id, action, target_type, target_id, details, sent_to_syslog, syslog_last_attempt, syslog_status
FROM audit_logs
ORDER BY timestamp DESC
LIMIT ?
`
    if err := r.db.SelectContext(ctx, &rows, query, limit); err != nil {
        return nil, err
    }

    out := make([]AuditLog, 0, len(rows))
    for _, rr := range rows {
        a := AuditLog{
            ID:                rr.ID.String,
            Timestamp:         rr.Timestamp.String,
            Action:            rr.Action.String,
            ObjectType:        rr.TargetType.String,
            Details:           rr.Details.String,
            SentToSyslog:      0,
            SyslogLastAttempt: nil,
            SyslogStatus:      nil,
        }
        if rr.ActorID.Valid {
            a.UserID = &rr.ActorID.String
        }
        if rr.TargetID.Valid {
            a.ObjectID = &rr.TargetID.String
        }
        if rr.SentToSyslog.Valid {
            a.SentToSyslog = int(rr.SentToSyslog.Int64)
        }
        if rr.SyslogLastAttempt.Valid {
            a.SyslogLastAttempt = &rr.SyslogLastAttempt.String
        }
        if rr.SyslogStatus.Valid {
            a.SyslogStatus = &rr.SyslogStatus.String
        }
        out = append(out, a)
    }
    return out, nil
}
