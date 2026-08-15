-- 0002_default_data.sql
-- Seed default roles, admin user placeholder, and example groups/policies where appropriate.
-- NOTE: Replace placeholder IDs and password hashes in production.

START TRANSACTION;

-- Default Roles
INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
VALUES
  ('role-admin-0001', 'admin', 'Full administrative access', JSON_ARRAY('admin:*'), NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
VALUES
  ('role-approver-0001', 'approver', 'Can approve requests for assigned groups', JSON_ARRAY('approvals:approve','approvals:list','certificates:view'), NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
VALUES
  ('role-viewer-0001', 'viewer', 'Read-only access to visible resources', JSON_ARRAY('certificates:view','policies:view','provisioners:view'), NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Example Groups
INSERT INTO groups (id, name, type, approver_role_id, description, created_at, updated_at)
VALUES
  ('group-users-0001', 'engineering', 'user', 'role-approver-0001', 'Engineering team', NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO groups (id, name, type, approver_role_id, description, created_at, updated_at)
VALUES
  ('group-devices-0001', 'iot-fleet', 'device', 'role-approver-0001', 'IoT fleet devices', NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Example admin user placeholder (do not use in production)
INSERT INTO users (id, username, display_name, email, password_hash, roles, groups, status, created_at, updated_at)
VALUES
  ('user-admin-0001', 'admin', 'Administrator', 'admin@example.local', NULL, JSON_ARRAY('admin'), JSON_ARRAY(), 'active', NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE username = VALUES(username);

COMMIT;
