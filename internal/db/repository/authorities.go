package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type Authority struct {
    ID           string `db:"id"`
    Name         string `db:"name"`
    Type         string `db:"type"`
    ParentID     *string `db:"parent_id"`
    Status       string `db:"status"`
    CertPEM      string `db:"cert_pem"`
    Fingerprint  string `db:"fingerprint"`
    KeyAlgorithm string `db:"key_algorithm"`
    KeySize      int    `db:"key_size"`
    ValidFrom    string `db:"valid_from"`
    ValidTo      string `db:"valid_to"`
    CreatedAt    string `db:"created_at"`
    UpdatedAt    string `db:"updated_at"`
}

type AuthorityRepository interface {
    Create(ctx context.Context, a *Authority) error
    GetByID(ctx context.Context, id string) (*Authority, error)
    List(ctx context.Context) ([]Authority, error)
    Update(ctx context.Context, a *Authority) error
    Delete(ctx context.Context, id string) error
}

type authorityRepository struct {
    db *sqlx.DB
}

func NewAuthorityRepository(db *sqlx.DB) AuthorityRepository {
    return &authorityRepository{db: db}
}

func (r *authorityRepository) Create(ctx context.Context, a *Authority) error {
    // TODO: implement SQL INSERT
    return nil
}

func (r *authorityRepository) GetByID(ctx context.Context, id string) (*Authority, error) {
    // TODO: implement SQL SELECT
    return nil, nil
}

func (r *authorityRepository) List(ctx context.Context) ([]Authority, error) {
    // TODO: implement SQL SELECT
    return nil, nil
}

func (r *authorityRepository) Update(ctx context.Context, a *Authority) error {
    // TODO: implement SQL UPDATE
    return nil
}

func (r *authorityRepository) Delete(ctx context.Context, id string) error {
    // TODO: implement SQL DELETE
    return nil
}
