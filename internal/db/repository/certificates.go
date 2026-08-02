package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type Certificate struct {
    ID             string `db:"id"`
    AuthorityID    string `db:"authority_id"`
    PolicyID       string `db:"policy_id"`
    ProvisionerID  *string `db:"provisioner_id"`
    SerialNumber   string `db:"serial_number"`
    SubjectCN      *string `db:"subject_cn"`
    SubjectO       *string `db:"subject_o"`
    SAN            string `db:"san"`
    CertPEM        string `db:"cert_pem"`
    IssuedAt       string `db:"issued_at"`
    ExpiresAt      string `db:"expires_at"`
    Status         string `db:"status"`
    RevocationReason *int `db:"revocation_reason"`
    RevocationTime *string `db:"revocation_time"`
    IssueMethod    string `db:"issue_method"`
    Metadata       *string `db:"metadata"`
    CreatedAt      string `db:"created_at"`
    UpdatedAt      string `db:"updated_at"`
}

type CertificateRepository interface {
    Create(ctx context.Context, c *Certificate) error
    GetByID(ctx context.Context, id string) (*Certificate, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error)
    Update(ctx context.Context, c *Certificate) error
    Delete(ctx context.Context, id string) error
}

type certificateRepository struct {
    db *sqlx.DB
}

func NewCertificateRepository(db *sqlx.DB) CertificateRepository {
    return &certificateRepository{db: db}
}

func (r *certificateRepository) Create(ctx context.Context, c *Certificate) error {
    return nil
}

func (r *certificateRepository) GetByID(ctx context.Context, id string) (*Certificate, error) {
    return nil, nil
}

func (r *certificateRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Certificate, error) {
    return nil, nil
}

func (r *certificateRepository) Update(ctx context.Context, c *Certificate) error {
    return nil
}

func (r *certificateRepository) Delete(ctx context.Context, id string) error {
    return nil
}
