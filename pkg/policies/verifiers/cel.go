package verifiers

import (
	"github.com/google/cel-go/cel"
	ita "github.com/in-toto/attestation/go/v1"
)

var celEnv *cel.Env

func initializeCelEnv() (err error) {
	if celEnv == nil {
		celEnv, err = cel.NewEnv(
			cel.Types(&ita.Statement{}),
			cel.Variable("this", cel.ObjectType("in_toto_attestation.v1.Statement")),
		)
		if err != nil {
			return
		}
	}
	return nil
}
