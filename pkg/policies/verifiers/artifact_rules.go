package verifiers

import (
	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	ita "github.com/in-toto/attestation/go/v1"
)

func verifyArtifactRules(statement *ita.Statement, ar *models.ArtifactRules, rule_name string) error {
	// TODO: implmeent artifact rules
	return nil
}
