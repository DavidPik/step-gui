CREATE INDEX idx_cert_authority ON certificates(authority_id);
CREATE INDEX idx_cert_policy ON certificates(policy_id);
CREATE INDEX idx_cert_status ON certificates(status);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_users_username ON users(username);
