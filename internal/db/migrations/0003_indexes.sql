-- 0003_indexes.sql
-- Add indexes to support repository queries and improve performance.

SET FOREIGN_KEY_CHECKS = 0;

-- Users
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Roles
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles (name);

-- Groups
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups (name);

-- Authorities
CREATE INDEX IF NOT EXISTS idx_authorities_name ON authorities (name);
CREATE INDEX IF NOT EXISTS idx_authorities_status ON authorities (status);

-- Provisioners
CREATE INDEX IF NOT EXISTS idx_provisioners_authority ON provisioners (authority_id);
CREATE INDEX IF NOT EXISTS idx_provisioners_name ON provisioners (name);

-- Policies
CREATE INDEX IF NOT EXISTS idx_policies_authority ON policies (authority_id);
CREATE INDEX IF NOT EXISTS idx_policies_name ON policies (name);

-- Devices
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices (group_id);

-- Certificates
CREATE INDEX IF NOT EXISTS idx_cert_authority ON certificates (authority_id);
CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates (serial_number);
CREATE INDEX IF NOT EXISTS idx_cert_owner_user ON certificates (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_cert_owner_device ON certificates (owner_device_id);
CREATE INDEX IF NOT EXISTS idx_cert_issued_at ON certificates (issued_at);

-- Approvals
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status);
CREATE INDEX IF NOT EXISTS idx_approvals_requester ON approvals (requester_id);
CREATE INDEX IF NOT EXISTS idx_approvals_approver ON approvals (approver_id);
CREATE INDEX IF NOT EXISTS idx_approvals_requested_at ON approvals (requested_at);

-- Audit logs
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor_id);

SET FOREIGN_KEY_CHECKS = 1;
