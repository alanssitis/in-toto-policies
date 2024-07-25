package verifiers

import (
	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	ita "github.com/in-toto/attestation/go/v1"
)

func verifyPredicateAttribute(statement *ita.Statement, pa *models.PredicateAttribute, rule_name string) error {
	return nil
}
