package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type Policy struct {
    ID                    string `db:"id"`
    AuthorityID           string `db:"authority_id"`
    Name                  string `db:"name"`
    Version               int    `db:"version"`
    SubjectType           string `db:"subject_type"`
    AllowedSanTypes       string `db:"allowed_san_types"`
    MinKeySize            int    `db:"min_key_size"`
    AllowedAlgorithms     string `db:"allowed_algorithms"`
    MaxValidityDays       int    `db:"max_validity_days"`
    ValidationRules       string `db:"validation_rules"`
    AllowedProvisionerIDs string `db:"allowed_provisioner_ids"`
    DefaultProvisionerID  *string `db:"default_provisioner_id"`
    OCSPConfig            *string `db:"ocsp_config"`
    CRLConfig             *string `db:"crl_config"`
    CreatedAt             string `db:"created_at"`
    UpdatedAt             string `db:"updated_at"`
}

type PolicyRepository interface {
    Create(ctx context.Context, p *Policy) error
    GetByID(ctx context.Context, id string) (*Policy, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Policy, error)
    Update(ctx context.Context, p *Policy) error
    Delete(ctx context.Context, id string) error
}

type policyRepository struct {
    db *sqlx.DB
}

func NewPolicyRepository(db *sqlx.DB) PolicyRepository {
    return &policyRepository{db: db}
}

func (r *policyRepository) Create(ctx context.Context, p *Policy) error {
    return nil
}

func (r *policyRepository) GetByID(ctx context.Context, id string) (*Policy, error) {
    return nil, nil
}

func (r *policyRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Policy, error) {
    return nil, nil
}

func (r *policyRepository) Update(ctx context.Context, p *Policy) error {
    return nil
}

func (r *policyRepository) Delete(ctx context.Context, id string) error {
    return nil
}
