package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type Provisioner struct {
    ID          string `db:"id"`
    AuthorityID string `db:"authority_id"`
    Name        string `db:"name"`
    Type        string `db:"type"`
    Config      string `db:"config"`
    CreatedAt   string `db:"created_at"`
    UpdatedAt   string `db:"updated_at"`
}

type ProvisionerRepository interface {
    Create(ctx context.Context, p *Provisioner) error
    GetByID(ctx context.Context, id string) (*Provisioner, error)
    ListByAuthority(ctx context.Context, authorityID string) ([]Provisioner, error)
    Update(ctx context.Context, p *Provisioner) error
    Delete(ctx context.Context, id string) error
}

type provisionerRepository struct {
    db *sqlx.DB
}

func NewProvisionerRepository(db *sqlx.DB) ProvisionerRepository {
    return &provisionerRepository{db: db}
}

func (r *provisionerRepository) Create(ctx context.Context, p *Provisioner) error {
    return nil
}

func (r *provisionerRepository) GetByID(ctx context.Context, id string) (*Provisioner, error) {
    return nil, nil
}

func (r *provisionerRepository) ListByAuthority(ctx context.Context, authorityID string) ([]Provisioner, error) {
    return nil, nil
}

func (r *provisionerRepository) Update(ctx context.Context, p *Provisioner) error {
    return nil
}

func (r *provisionerRepository) Delete(ctx context.Context, id string) error {
    return nil
}
