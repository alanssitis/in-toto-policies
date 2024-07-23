package policies

type PolicyDocument struct {
	Functionaries map[string]*Functionary `yaml:"functionaries" json:"functionaries"`
	Attestations  []*Attestation          `yaml:"attestations" json:"attestations"`
}

type Functionary struct {
	KeyType string `yaml:"keyType"`
	Scheme  string `yaml:"scheme"`
	KeyPath string `yaml:"keyPath"`
}

type Attestation struct {
	Name                 string    `yaml:"name" json:"name"`
	PredicateType        string    `yaml:"predicateType" json:"predicateType"`
	Policies             []*Policy `yaml:"policies" json:"policies"`
	AllowedFunctionaries []string  `yaml:"allowedFunctionaries" json:"allowedFunctionaries"`
}

type Policy struct {
	Type       string      `yaml:"type" json:"type"`
	Definition interface{} `yaml:"definition" json:"definition"`
}

type PredicateAttribute struct {
	Expressions []string `yaml:"expressions" json:"expressions"`
	// Potentially add a field that holds what expression language is used
}

type ArtifactRules struct {
	Field string   `yaml:"field" json:"field"`
	Rules []string `yaml:"rules" json:"rules"`
}
