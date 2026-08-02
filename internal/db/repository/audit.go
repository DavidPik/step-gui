package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type AuditLog struct {
    ID                string  `db:"id"`
    Timestamp         string  `db:"timestamp"`
    UserID            *string `db:"user_id"`
    Action            string  `db:"action"`
    ObjectType        string  `db:"object_type"`
    ObjectID          *string `db:"object_id"`
    Details           string  `db:"details"`
    SentToSyslog      int     `db:"sent_to_syslog"`
    SyslogLastAttempt *string `db:"syslog_last_attempt"`
    SyslogStatus      *string `db:"syslog_status"`
}

type AuditRepository interface {
    Create(ctx context.Context, a *AuditLog) error
    List(ctx context.Context, limit int) ([]AuditLog, error)
}

type auditRepository struct {
    db *sqlx.DB
}

func NewAuditRepository(db *sqlx.DB) AuditRepository {
    return &auditRepository{db: db}
}

func (r *auditRepository) Create(ctx context.Context, a *AuditLog) error {
    return nil
}

func (r *auditRepository) List(ctx context.Context, limit int) ([]AuditLog, error) {
    return nil, nil
}
