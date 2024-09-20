package verifiers

import (
	"errors"
	"fmt"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"github.com/alecthomas/participle/v2"
	ita "github.com/in-toto/attestation/go/v1"
)

type ArtifactRule interface{ value() }

type Require struct {
	Pattern string `"REQUIRE" @String`
}

func (f Require) value() {}

type Allow struct {
	Pattern string `"ALLOW" @String`
}

func (f Allow) value() {}

type Disallow struct {
	Pattern string `"DISALLOW" @String`
}

func (f Disallow) value() {}

type Match struct {
	Pattern           string  `"MATCH" @String`
	SourcePrefix      *string `("IN" @String)?`
	Field             string  `"WITH" @String`
	DestinationPrefix *string `("IN" @String)?`
}

func (f Match) value() {}

type Mismatch struct {
	Pattern           string  `"MISMATCH" @String`
	SourcePrefix      *string `("IN" @String)?`
	Field             string  `"WITH" @String`
	DestinationPrefix *string `("IN" @String)?`
}

func (f Mismatch) value() {}

var (
	arParser = participle.MustBuild[ArtifactRule](
		participle.Union[ArtifactRule](
			Require{},
			Allow{},
			Disallow{},
			Match{},
			Mismatch{},
		),
		participle.UseLookahead(1024),
	)
	fieldArtifacts map[string]*[]ita.ResourceDescriptor = make(map[string]*[]ita.ResourceDescriptor)
)

func verifyArtifactRules(statement *ita.Statement, ar *models.ArtifactRules, rule_name string) error {
	for _, r := range ar.Rules {
		rule, err := arParser.ParseString("", r)
		if err != nil {
			return err
		}
		// TODO: finish implementing
		switch r := (*rule).(type) {
		case Require:
			fmt.Printf("require %s\n", r.Pattern)
		case Allow:
			fmt.Printf("allow %s\n", r.Pattern)
		case Disallow:
			fmt.Printf("disallow %s\n", r.Pattern)
		case Match:
			fmt.Printf("match %s\n", r.Pattern)
		case Mismatch:
			fmt.Printf("mismatch %s\n", r.Pattern)
		default:
			return errors.New("Unknown artifact rule type")
		}
	}
	return nil
}
