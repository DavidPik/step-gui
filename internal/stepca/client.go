package stepca

import (
    "bytes"
    "crypto/x509"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "time"
)

type Client struct {
    BaseURL     string
    Provisioner string
    Key         []byte
    http        *http.Client
}

func New(baseURL, prov string, key []byte) *Client {
    return &Client{
        BaseURL:     baseURL,
        Provisioner: prov,
        Key:         key,
        http: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

//
// INTERNAL HELPERS
//

func (c *Client) post(path string, body any) ([]byte, error) {
    b, err := json.Marshal(body)
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewReader(b))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")

    res, err := c.http.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    data, _ := io.ReadAll(res.Body)

    if res.StatusCode >= 300 {
        return nil, fmt.Errorf("step-ca error %d: %s", res.StatusCode, string(data))
    }

    return data, nil
}

func (c *Client) get(path string) ([]byte, error) {
    req, err := http.NewRequest("GET", c.BaseURL+path, nil)
    if err != nil {
        return nil, err
    }

    res, err := c.http.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    data, _ := io.ReadAll(res.Body)

    if res.StatusCode >= 300 {
        return nil, fmt.Errorf("step-ca error %d: %s", res.StatusCode, string(data))
    }

    return data, nil
}

//
// API STRUCTURES
//

type SignRequest struct {
    CSR         string `json:"csr"`
    NotAfter    string `json:"notAfter,omitempty"`
    NotBefore   string `json:"notBefore,omitempty"`
    Provisioner string `json:"provisioner"`
}

type SignResponse struct {
    CertPEM string `json:"crt"`
    Chain   string `json:"chain"`
}

type RevokeRequest struct {
    SerialNumber string `json:"serial"`
    Reason       int    `json:"reason"`
    Provisioner  string `json:"provisioner"`
}

type Provisioner struct {
    Name string `json:"name"`
    Type string `json:"type"`
}

//
// PUBLIC API
//

// SignCSR → POST /sign
func (c *Client) SignCSR(csrPEM string) (*SignResponse, error) {
    req := SignRequest{
        CSR:         csrPEM,
        Provisioner: c.Provisioner,
    }

    data, err := c.post("/sign", req)
    if err != nil {
        return nil, err
    }

    var out SignResponse
    if err := json.Unmarshal(data, &out); err != nil {
        return nil, err
    }

    return &out, nil
}

// RevokeCertificate → POST /revoke
func (c *Client) RevokeCertificate(serial string, reason int) error {
    req := RevokeRequest{
        SerialNumber: serial,
        Reason:       reason,
        Provisioner:  c.Provisioner,
    }

    _, err := c.post("/revoke", req)
    return err
}

// ListProvisioners → GET /provisioners
func (c *Client) ListProvisioners() ([]Provisioner, error) {
    data, err := c.get("/provisioners")
    if err != nil {
        return nil, err
    }

    var out []Provisioner
    if err := json.Unmarshal(data, &out); err != nil {
        return nil, err
    }

    return out, nil
}

// GetRoots → GET /roots
func (c *Client) GetRoots() ([]*x509.Certificate, error) {
    data, err := c.get("/roots")
    if err != nil {
        return nil, err
    }

    var pemList []string
    if err := json.Unmarshal(data, &pemList); err != nil {
        return nil, err
    }

    var certs []*x509.Certificate
    for _, pem := range pemList {
        block, _ := pemDecode(pem)
        if block == nil {
            return nil, errors.New("invalid root certificate")
        }
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            return nil, err
        }
        certs = append(certs, cert)
    }

    return certs, nil
}

// Health → GET /health
func (c *Client) Health() error {
    _, err := c.get("/health")
    return err
}
