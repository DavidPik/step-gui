package api

type AuthorityCreateRequest struct {
    Name         string  `json:"name"`
    Type         string  `json:"type"`        // "root" | "sub"
    ParentID     *string `json:"parent_id"`   // optional
    CertPEM      string  `json:"cert_pem"`
    Fingerprint  string  `json:"fingerprint"`
    KeyAlgorithm string  `json:"key_algorithm"`
    KeySize      int     `json:"key_size"`
    ValidFrom    string  `json:"valid_from"`  // ISO8601
    ValidTo      string  `json:"valid_to"`    // ISO8601
}

type AuthorityUpdateRequest struct {
    Name         string  `json:"name"`
    Status       string  `json:"status"`      // "active" | "retired"
    CertPEM      string  `json:"cert_pem"`
    Fingerprint  string  `json:"fingerprint"`
    KeyAlgorithm string  `json:"key_algorithm"`
    KeySize      int     `json:"key_size"`
    ValidFrom    string  `json:"valid_from"`
    ValidTo      string  `json:"valid_to"`
}

type PolicyCreateRequest struct {
    AuthorityID           string   `json:"authority_id"`
    Name                  string   `json:"name"`
    Version               int      `json:"version"`
    SubjectType           string   `json:"subject_type"`
    AllowedSanTypes       []string `json:"allowed_san_types"`
    MinKeySize            int      `json:"min_key_size"`
    AllowedAlgorithms     []string `json:"allowed_algorithms"`
    MaxValidityDays       int      `json:"max_validity_days"`
    ValidationRules       map[string]any `json:"validation_rules"`
    AllowedProvisionerIDs []string `json:"allowed_provisioner_ids"`
    DefaultProvisionerID  *string  `json:"default_provisioner_id"`
    OCSPConfig            map[string]any `json:"ocsp_config"`
    CRLConfig             map[string]any `json:"crl_config"`
}

type PolicyUpdateRequest = PolicyCreateRequest

type ProvisionerCreateRequest struct {
    AuthorityID string         `json:"authority_id"`
    Name        string         `json:"name"`
    Type        string         `json:"type"`   // jwk | acme | oidc | x5c
    Config      map[string]any `json:"config"`
}

type ProvisionerUpdateRequest = ProvisionerCreateRequest

type CertificateIssueRequest struct {
    AuthorityID string `json:"authority_id"`
    PolicyID    string `json:"policy_id"`
    CSR         string `json:"csr_pem"`
    IssueMethod string `json:"issue_method"` // manual | provisioner
}

type CertificateUpdateRequest struct {
    Metadata map[string]any `json:"metadata"`
}

type UserCreateRequest struct {
    Username    string `json:"username"`
    DisplayName string `json:"display_name"`
    Email       string `json:"email"`
    Status      string `json:"status"`
    AuthSource  string `json:"auth_source"`
}

type UserUpdateRequest = UserCreateRequest
