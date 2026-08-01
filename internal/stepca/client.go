package stepca

type Client struct {
    BaseURL     string
    Provisioner string
    Key         []byte
}

func New(baseURL, prov string, key []byte) *Client {
    return &Client{BaseURL: baseURL, Provisioner: prov, Key: key}
}
