-- Root uživatel
INSERT INTO users (id, username, display_name, email, status, auth_source, created_at, updated_at)
VALUES (
    UUID(),
    'root',
    'Root Administrator',
    'root@example.local',
    'active',
    'local',
    NOW(),
    NOW()
);
-- Role CA_ADMIN
INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
VALUES (
    UUID(),
    'CA_ADMIN',
    'Full access to CA management',
    JSON_ARRAY('manage_authorities','manage_policies','manage_provisioners','issue_certificates','revoke_certificates'),
    NOW(),
    NOW()
);
-- Role USER
INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
VALUES (
    UUID(),
    'USER',
    'Basic user role',
    JSON_ARRAY('view_certificates'),
    NOW(),
    NOW()
);
-- Root user gets CA_ADMIN
INSERT INTO user_roles (user_id, role_id, authority_id)
SELECT u.id, r.id, NULL
FROM users u, roles r
WHERE u.username='root' AND r.name='CA_ADMIN';
