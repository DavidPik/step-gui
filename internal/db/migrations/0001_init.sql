-- 0001_init.sql
-- Initial schema for MariaDB (InnoDB). Designed to match repository layer expectations.

SET FOREIGN_KEY_CHECKS = 0;

-- Roles
CREATE TABLE IF NOT EXISTS roles (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT NULL,
  permissions JSON NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Users
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255) NULL,
  email VARCHAR(320) NULL,
  password_hash VARCHAR(512) NULL,
  roles JSON NOT NULL DEFAULT ('[]'),
  groups JSON NOT NULL DEFAULT ('[]'),
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  auth_source VARCHAR(128) NULL,
  mfa_config JSON NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Groups
CREATE TABLE IF NOT EXISTS groups (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  type VARCHAR(32) NOT NULL, -- user | device
  approver_role_id VARCHAR(36) NULL,
  description TEXT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_groups_approver_role FOREIGN KEY (approver_role_id) REFERENCES roles(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Authorities (CAs)
CREATE TABLE IF NOT EXISTS authorities (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  type VARCHAR(32) NOT NULL, -- root | sub
  parent_id VARCHAR(36) NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  cert_pem LONGTEXT NULL,
  fingerprint VARCHAR(255) NULL,
  key_algorithm VARCHAR(64) NULL,
  key_size INT NULL,
  valid_from DATETIME(6) NULL,
  valid_to DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_authorities_parent FOREIGN KEY (parent_id) REFERENCES authorities(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Provisioners (StepCA / external provisioners)
CREATE TABLE IF NOT EXISTS provisioners (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  authority_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(128) NOT NULL,
  config JSON NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_provisioners_authority FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Policies
CREATE TABLE IF NOT EXISTS policies (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  authority_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(64) NOT NULL,
  subject_type VARCHAR(64) NOT NULL,
  allowed_san_types JSON NULL,
  min_key_size INT NULL,
  allowed_algorithms JSON NULL,
  max_validity_days INT NULL,
  validation_rules JSON NULL,
  allowed_provisioner_ids JSON NULL,
  default_provisioner_id VARCHAR(36) NULL,
  ocsp_config JSON NULL,
  crl_config JSON NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_policies_authority FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE,
  CONSTRAINT fk_policies_default_provisioner FOREIGN KEY (default_provisioner_id) REFERENCES provisioners(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Devices
CREATE TABLE IF NOT EXISTS devices (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  serial VARCHAR(255) NULL,
  owner_user_id VARCHAR(36) NULL,
  group_id VARCHAR(36) NULL,
  metadata JSON NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_devices_owner FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_devices_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Certificates
CREATE TABLE IF NOT EXISTS certificates (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  authority_id VARCHAR(36) NOT NULL,
  serial_number VARCHAR(255) NOT NULL,
  subject TEXT NOT NULL,
  sans JSON NULL,
  owner_user_id VARCHAR(36) NULL,
  owner_device_id VARCHAR(36) NULL,
  provisioner_id VARCHAR(36) NULL,
  policy_id VARCHAR(36) NULL,
  issued_at DATETIME(6) NOT NULL,
  not_before DATETIME(6) NULL,
  not_after DATETIME(6) NULL,
  revoked TINYINT(1) NOT NULL DEFAULT 0,
  revoked_at DATETIME(6) NULL,
  revocation_reason TEXT NULL,
  pem LONGTEXT NULL,
  approval_id VARCHAR(36) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_cert_authority FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE,
  CONSTRAINT fk_cert_owner_user FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_cert_owner_device FOREIGN KEY (owner_device_id) REFERENCES devices(id) ON DELETE SET NULL,
  CONSTRAINT fk_cert_provisioner FOREIGN KEY (provisioner_id) REFERENCES provisioners(id) ON DELETE SET NULL,
  CONSTRAINT fk_cert_policy FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Approvals
CREATE TABLE IF NOT EXISTS approvals (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  requester_id VARCHAR(36) NOT NULL,
  target_type VARCHAR(64) NOT NULL, -- user | device | certificate | other
  target_id VARCHAR(36) NULL,
  policy_id VARCHAR(36) NULL,
  approver_id VARCHAR(36) NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending|approved|rejected|error
  requested_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  decided_at DATETIME(6) NULL,
  reason TEXT NULL,
  payload JSON NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_approvals_requester FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_approvals_approver FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs (append-only)
CREATE TABLE IF NOT EXISTS audit_logs (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  timestamp DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  actor_id VARCHAR(36) NULL,
  action VARCHAR(255) NOT NULL,
  target_type VARCHAR(128) NULL,
  target_id VARCHAR(36) NULL,
  details JSON NOT NULL,
  sent_to_syslog TINYINT(1) NOT NULL DEFAULT 0,
  syslog_last_attempt DATETIME(6) NULL,
  syslog_status VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
