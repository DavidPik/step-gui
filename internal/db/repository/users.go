package repository

import (
    "context"
    "github.com/jmoiron/sqlx"
)

type User struct {
    ID          string `db:"id"`
    Username    string `db:"username"`
    DisplayName string `db:"display_name"`
    Email       string `db:"email"`
    Status      string `db:"status"`
    AuthSource  string `db:"auth_source"`
    MFAConfig   *string `db:"mfa_config"`
    CreatedAt   string `db:"created_at"`
    UpdatedAt   string `db:"updated_at"`
}

type UserRepository interface {
    Create(ctx context.Context, u *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    GetByUsername(ctx context.Context, username string) (*User, error)
    List(ctx context.Context) ([]User, error)
    Update(ctx context.Context, u *User) error
    Delete(ctx context.Context, id string) error
}

type userRepository struct {
    db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, u *User) error {
    return nil
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*User, error) {
    return nil, nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
    return nil, nil
}

func (r *userRepository) List(ctx context.Context) ([]User, error) {
    return nil, nil
}

func (r *userRepository) Update(ctx context.Context, u *User) error {
    return nil
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
    return nil
}
