CREATE TABLE authorities (
    id              CHAR(36)        NOT NULL PRIMARY KEY,
    name            VARCHAR(128)    NOT NULL,
    type            ENUM('root','sub') NOT NULL,
    parent_id       CHAR(36)        NULL,
    status          ENUM('active','retired') NOT NULL DEFAULT 'active',
    cert_pem        TEXT            NOT NULL,
    fingerprint     VARCHAR(128)    NOT NULL,
    key_algorithm   VARCHAR(32)     NOT NULL,
    key_size        INT             NOT NULL,
    valid_from      DATETIME        NOT NULL,
    valid_to        DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL,
    updated_at      DATETIME        NOT NULL,

    CONSTRAINT fk_authorities_parent
        FOREIGN KEY (parent_id) REFERENCES authorities(id)
        ON DELETE SET NULL,

    CONSTRAINT uq_authorities_name UNIQUE (name),
    CONSTRAINT uq_authorities_fingerprint UNIQUE (fingerprint)
);
CREATE TABLE policies (
    id                      CHAR(36)        NOT NULL PRIMARY KEY,
    authority_id            CHAR(36)        NOT NULL,
    name                    VARCHAR(128)    NOT NULL,
    version                 INT             NOT NULL,
    subject_type            VARCHAR(32)     NOT NULL,
    allowed_san_types       JSON            NOT NULL,
    min_key_size            INT             NOT NULL,
    allowed_algorithms      JSON            NOT NULL,
    max_validity_days       INT             NOT NULL,
    validation_rules        JSON            NOT NULL,
    allowed_provisioner_ids JSON            NOT NULL,
    default_provisioner_id  CHAR(36)        NULL,
    ocsp_config             JSON            NULL,
    crl_config              JSON            NULL,
    created_at              DATETIME        NOT NULL,
    updated_at              DATETIME        NOT NULL,

    CONSTRAINT fk_policies_authority
        FOREIGN KEY (authority_id) REFERENCES authorities(id)
        ON DELETE CASCADE
);
CREATE TABLE provisioners (
    id              CHAR(36)        NOT NULL PRIMARY KEY,
    authority_id    CHAR(36)        NOT NULL,
    name            VARCHAR(128)    NOT NULL,
    type            ENUM('jwk','acme','oidc','x5c') NOT NULL,
    config          JSON            NOT NULL,
    created_at      DATETIME        NOT NULL,
    updated_at      DATETIME        NOT NULL,

    CONSTRAINT fk_provisioners_authority
        FOREIGN KEY (authority_id) REFERENCES authorities(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_provisioners_name UNIQUE (authority_id, name)
);
CREATE TABLE certificates (
    id                  CHAR(36)        NOT NULL PRIMARY KEY,
    authority_id        CHAR(36)        NOT NULL,
    policy_id           CHAR(36)        NOT NULL,
    provisioner_id      CHAR(36)        NULL,
    serial_number       VARCHAR(64)     NOT NULL,
    subject_cn          VARCHAR(256)    NULL,
    subject_o           VARCHAR(256)    NULL,
    san                 JSON            NOT NULL,
    cert_pem            TEXT            NOT NULL,
    issued_at           DATETIME        NOT NULL,
    expires_at          DATETIME        NOT NULL,
    status              ENUM('valid','expiring','expired','revoked') NOT NULL,
    revocation_reason   INT             NULL,
    revocation_time     DATETIME        NULL,
    issue_method        VARCHAR(32)     NOT NULL,
    metadata            JSON            NULL,
    created_at          DATETIME        NOT NULL,
    updated_at          DATETIME        NOT NULL,

    CONSTRAINT fk_cert_authority
        FOREIGN KEY (authority_id) REFERENCES authorities(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_cert_policy
        FOREIGN KEY (policy_id) REFERENCES policies(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_cert_provisioner
        FOREIGN KEY (provisioner_id) REFERENCES provisioners(id)
        ON DELETE SET NULL,

    CONSTRAINT uq_cert_serial UNIQUE (serial_number)
);
CREATE TABLE users (
    id              CHAR(36)        NOT NULL PRIMARY KEY,
    username        VARCHAR(64)     NOT NULL UNIQUE,
    display_name    VARCHAR(128)    NOT NULL,
    email           VARCHAR(256)    NOT NULL,
    status          ENUM('active','blocked') NOT NULL DEFAULT 'active',
    auth_source     VARCHAR(32)     NOT NULL,
    mfa_config      JSON            NULL,
    created_at      DATETIME        NOT NULL,
    updated_at      DATETIME        NOT NULL
);
CREATE TABLE roles (
    id              CHAR(36)        NOT NULL PRIMARY KEY,
    name            VARCHAR(64)     NOT NULL UNIQUE,
    description     VARCHAR(256)    NULL,
    permissions     JSON            NOT NULL,
    created_at      DATETIME        NOT NULL,
    updated_at      DATETIME        NOT NULL
);
CREATE TABLE user_roles (
    user_id         CHAR(36)        NOT NULL,
    role_id         CHAR(36)        NOT NULL,
    authority_id    CHAR(36)        NULL,

    PRIMARY KEY (user_id, role_id, authority_id),

    CONSTRAINT fk_ur_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ur_role
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ur_authority
        FOREIGN KEY (authority_id) REFERENCES authorities(id)
        ON DELETE CASCADE
);
CREATE TABLE audit_logs (
    id                  CHAR(36)        NOT NULL PRIMARY KEY,
    timestamp           DATETIME        NOT NULL,
    user_id             CHAR(36)        NULL,
    action              VARCHAR(64)     NOT NULL,
    object_type         VARCHAR(32)     NOT NULL,
    object_id           CHAR(36)        NULL,
    details             JSON            NOT NULL,
    sent_to_syslog      TINYINT(1)      NOT NULL DEFAULT 0,
    syslog_last_attempt DATETIME        NULL,
    syslog_status       VARCHAR(64)     NULL,

    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL
);
