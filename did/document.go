package did

type Resolver interface {
	Resolve(did string) (*Document, error)
}

// Default context: 'https://w3id.org/did/v1'
type Document struct {
	Context        string            `json:"@context"`
	Id             string            `json:"id,omitempty"`
	PublicKey      []PublicKey       `json:"publicKey,omitempty"`
	Authentication []interface{}     `json:"authentication,omitempty"`
	Service        []ServiceEndpoint `json:"service,omitempty"`
	Created        string            `json:"created"`
	Updated        string            `json:"updated,omitempty"`
	Authorization  Authorization     `json:"authorization,omitempty"`
}

type Authorization struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Grant []string               `json:"grant"`
	When  map[string]interface{} `json:"when"`
	Id    string                 `json:"id"`
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
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58,omitempty"`
	EthereumAddress string `json:"ethereumAddress,omitempty"`
}

type Authentication struct {
	Type      string `json:"type"`
	PublicKey string `json:"publicKey"`
}
