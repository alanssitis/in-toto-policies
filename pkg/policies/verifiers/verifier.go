package verifiers

import (
	"encoding/json"
	"errors"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	ita "github.com/in-toto/attestation/go/v1"
)

func VerifyPolicy(statement *ita.Statement, policy *models.Policy, rule_name string) error {
	m, err := json.Marshal(policy.Definition)
	if err != nil {
		return err
	}
	switch policy.Type {
	case "https://in-toto.io/policy/artifact-rules/v0.1":
		var ar models.ArtifactRules
		err = json.Unmarshal(m, &ar)
		if err != nil {
			return err
		}
		return verifyArtifactRules(statement, &ar, rule_name)
	case "https://in-toto.io/policy/predicate-attribute/v0.1":
		var pa models.PredicateAttribute
		err = json.Unmarshal(m, &pa)
		if err != nil {
			return err
		}
		return verifyPredicateAttribute(statement, &pa, rule_name)
	default:
		return errors.New("unsupported policy type")
	}
}
