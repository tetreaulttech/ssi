package did

type Resolver interface {
	Resolve(did string) (*Document, error)
}

// Default context: 'https://w3id.org/did/v1'
type Document struct {
	Context        string            `json:"@context"`
	Id             string            `json:"id"`
	PublicKey      []PublicKey       `json:"publicKey"`
	Authentication []Authentication  `json:"authentication"`
	Service        []ServiceEndpoint `json:"service"`
	Created        string            `json:"created"`
	Updated        string            `json:"updated"`
}

type ServiceEndpoint struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
	Description     string `json:"description"`
}

type PublicKey struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	Owner           string `json:"owner"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
	EthereumAddress string `json:"ethereumAddress"`
}

type Authentication struct {
	Type      string `json:"type"`
	PublicKey string `json:"publicKey"`
}
