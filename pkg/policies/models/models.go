package models

type PolicyDocument struct {
	Functionaries    []*Functionary     `yaml:"functionaries" json:"functionaries"`
	AttestationRules []*AttestationRule `yaml:"attestationRules" json:"attestationRules"`
}

type Functionary struct {
	Name          string `yaml:"name" json:"name"`
	PublicKeyPath string `yaml:"publicKeyPath" json:"publicKeyPath"`
	Scheme        string `yaml:"scheme" json:"scheme"`
}

type AttestationRule struct {
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
