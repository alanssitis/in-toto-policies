package verifiers

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"github.com/google/cel-go/cel"
	ita "github.com/in-toto/attestation/go/v1"
)

var (
	statements map[string]any = make(map[string]any)
)

func verifyPredicateAttribute(s *ita.Statement, pa *models.PredicateAttribute, rule_name string) (err error) {
	if err = initializeCelEnv(); err != nil {
		return
	}

	for _, e := range pa.Expressions {
		ast, issues := celEnv.Compile(e)
		if err = issues.Err(); err != nil {
			return
		}
		if !reflect.DeepEqual(ast.OutputType(), cel.BoolType) {
			return errors.New("predicate attribute expression must resolve to a boolean")
		}
		program, err := celEnv.Program(ast)
		if err != nil {
			return err
		}
		statements["this"] = s
		out, _, err := program.Eval(statements)
		if err != nil {
			return err
		}
		if !out.Value().(bool) {
			return errors.New(fmt.Sprintf("predicate attribute rule failed: %s", e))
		}
	}

	celEnv.Extend(cel.Variable(rule_name, cel.ObjectType("in_toto_attestation.v1.Statement")))
	statements[rule_name] = s
	return nil
}
