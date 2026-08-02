package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type Role struct {
    ID          string `db:"id"`
    Name        string `db:"name"`
    Description *string `db:"description"`
    Permissions string `db:"permissions"`
    CreatedAt   string `db:"created_at"`
    UpdatedAt   string `db:"updated_at"`
}

type RoleRepository interface {
    Create(ctx context.Context, r *Role) error
    GetByID(ctx context.Context, id string) (*Role, error)
    GetByName(ctx context.Context, name string) (*Role, error)
    List(ctx context.Context) ([]Role, error)
    Update(ctx context.Context, r *Role) error
    Delete(ctx context.Context, id string) error
}

type roleRepository struct {
    db *sqlx.DB
}

func NewRoleRepository(db *sqlx.DB) RoleRepository {
    return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *Role) error {
    return nil
}

func (r *roleRepository) GetByID(ctx context.Context, id string) (*Role, error) {
    return nil, nil
}

func (r *roleRepository) GetByName(ctx context.Context, name string) (*Role, error) {
    return nil, nil
}

func (r *roleRepository) List(ctx context.Context) ([]Role, error) {
    return nil, nil
}

func (r *roleRepository) Update(ctx context.Context, role *Role) error {
    return nil
}

func (r *roleRepository) Delete(ctx context.Context, id string) error {
    return nil
}
