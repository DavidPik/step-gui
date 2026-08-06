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
