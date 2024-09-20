package verifiers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"strings"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"github.com/alecthomas/participle/v2"
	lpb "github.com/in-toto/attestation/go/predicates/link/v0"
	ita "github.com/in-toto/attestation/go/v1"
	"github.com/stoewer/go-strcase"
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
		participle.Unquote("String"),
	)
	fieldArtifacts map[string]map[string]*ita.ResourceDescriptor = make(map[string]map[string]*ita.ResourceDescriptor)
)

func verifyArtifactRules(s *ita.Statement, ar *models.ArtifactRules, rule_name string) error {
	rds, err := getArtifactResourceDescriptors(s, ar.Field)
	if err != nil {
		return err
	}
	rdsCopy := maps.Clone(rds)

	for _, r := range ar.Rules {
		rule, err := arParser.ParseString("", r)
		if err != nil {
			return err
		}
		switch r := (*rule).(type) {
		case Require:
			err = applyRequireRule(r, rds)
		case Allow:
			err = applyAllowRule(r, rds)
		case Disallow:
			err = applyDisallowRule(r, rds)
		case Match:
			err = applyMatchRule(r, rds)
		case Mismatch:
			err = applyMismatchRule(r, rds)
		default:
			err = errors.New("Unknown artifact rule type")
		}
		if err != nil {
			return err
		}
	}
	fieldArtifacts[formatFieldArtifactName(rule_name, ar.Field)] = rdsCopy
	return nil
}

func getArtifactResourceDescriptors(s *ita.Statement, field string) (map[string]*ita.ResourceDescriptor, error) {
	var rs, rd reflect.Value
	formattedField := formatFieldPath(field)
	if strings.HasPrefix(formattedField, "Predicate.") {
		// Maybe more powerful reflection like what CEL uses so there's no need for this
		formattedField = strings.TrimPrefix(formattedField, "Predicate.")
		switch s.PredicateType {
		case "https://in-toto.io/attestation/link/v0.3":
			var link lpb.Link
			data, err := s.Predicate.MarshalJSON()
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(data, &link)
			if err != nil {
				return nil, err
			}
			rs = reflect.ValueOf(&link)
		default:
			return nil, errors.New("unsupported predicate type")
		}
	} else {
		rs = reflect.ValueOf(s)
	}
	rd = reflect.Indirect(rs).FieldByName(formattedField)
	if !rd.IsValid() {
		return nil, fmt.Errorf("statement field does not exist: %s", field)
	}
	rds, successful := rd.Interface().([]*ita.ResourceDescriptor)
	if !successful {
		return nil, fmt.Errorf("statement field is not a collection of resource descriptor: %s", field)
	}
	rds_map := make(map[string]*ita.ResourceDescriptor)
	for _, rd := range rds {
		rds_map[rd.Name] = rd
	}
	return rds_map, nil
}

func formatFieldPath(field string) string {
	fields := strings.Split(strings.TrimPrefix(field, "this."), ".")
	for i, f := range fields {
		fields[i] = strcase.UpperCamelCase(f)
	}
	return strings.Join(fields, ".")
}

func formatFieldArtifactName(ruleName, field string) string {
	if strings.HasPrefix(field, "this.") {
		return strings.Replace(field, "this", ruleName, 1)
	}
	return ruleName + "." + field
}

func applyRequireRule(r Require, rds map[string]*ita.ResourceDescriptor) error {
	seen := false
	err := independentRuleCheck(
		r.Pattern,
		rds,
		func(name string, rds map[string]*ita.ResourceDescriptor) error {
			delete(rds, r.Pattern)
			seen = true
			return nil
		})
	if err != nil {
		return err
	}
	if seen {
		return nil
	}
	return fmt.Errorf("did match with required resource pattern '%s'", r.Pattern)
}

func applyAllowRule(a Allow, rds map[string]*ita.ResourceDescriptor) error {
	return independentRuleCheck(
		a.Pattern,
		rds,
		func(name string, rds map[string]*ita.ResourceDescriptor) error {
			delete(rds, a.Pattern)
			return nil
		})
}

func applyDisallowRule(d Disallow, rds map[string]*ita.ResourceDescriptor) error {
	return independentRuleCheck(
		d.Pattern,
		rds,
		func(name string, rds map[string]*ita.ResourceDescriptor) error {
			return fmt.Errorf(
				"matched with a disallowed resource pattern '%s': %s",
				d.Pattern,
				name,
			)
		})
}

func independentRuleCheck(p string, rds map[string]*ita.ResourceDescriptor, f func(string, map[string]*ita.ResourceDescriptor) error) (err error) {
	if !strings.Contains(p, "*") {
		if _, ok := rds[p]; ok {
			err = f(p, rds)
			if err != nil {
				return
			}
		}
	} else {
		pattern := strings.Replace(p, "*", ".*", -1)
		for name := range rds {
			match, err := regexp.MatchString(pattern, name)
			if err != nil {
				return err
			}
			if match {
				err = f(name, rds)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func applyMatchRule(m Match, rds map[string]*ita.ResourceDescriptor) error {
	return relationalRuleCheck(
		m.Pattern,
		m.Field,
		m.SourcePrefix,
		m.DestinationPrefix,
		rds,
		func(rd1, rd2 *ita.ResourceDescriptor, rds map[string]*ita.ResourceDescriptor, name string) error {
			if equalResourceDescriptor(rd1, rd2) {
				delete(rds, name)
			}
			return nil
		})
}

func applyMismatchRule(m Mismatch, rds map[string]*ita.ResourceDescriptor) error {
	return relationalRuleCheck(
		m.Pattern,
		m.Field,
		m.SourcePrefix,
		m.DestinationPrefix,
		rds,
		func(rd1, rd2 *ita.ResourceDescriptor, rds map[string]*ita.ResourceDescriptor, name string) error {
			if !equalResourceDescriptor(rd1, rd2) {
				delete(rds, name)
			}
			return nil
		})
}

func relationalRuleCheck(p, field string, sp, dp *string, rds map[string]*ita.ResourceDescriptor, f func(*ita.ResourceDescriptor, *ita.ResourceDescriptor, map[string]*ita.ResourceDescriptor, string) error) error {
	if !strings.Contains(p, "*") {
		srcPattern := p
		destPattern := srcPattern
		if sp != nil {
			srcPattern = *sp + srcPattern
		}
		if dp != nil {
			destPattern = *dp + srcPattern
		}
		srcRd, srcOk := rds[srcPattern]
		destRd, destOk := fieldArtifacts[field][destPattern]
		if srcOk && destOk {
			f(srcRd, destRd, rds, srcPattern)
		}
	} else {
		srcPattern := strings.Replace(p, "*", ".*", -1)
		if sp != nil {
			srcPattern = *sp + srcPattern
		}
		for srcName, srcRd := range rds {
			match, err := regexp.MatchString(srcPattern, srcName)
			if err != nil {
				return err
			}
			if match {
				destPattern := srcName
				if sp != nil {
					destPattern = strings.TrimPrefix(destPattern, *sp)
				}
				if dp != nil {
					destPattern = *dp + srcPattern
				}
				destRd, destOk := fieldArtifacts[field][destPattern]
				if destOk {
					f(srcRd, destRd, rds, srcPattern)
				}
			}
		}
	}
	return nil
}

func equalResourceDescriptor(rd1, rd2 *ita.ResourceDescriptor) bool {
	if rd1 == rd2 {
		return true
	}
	// Not comparing annotations
	return rd1.Name == rd2.Name &&
		rd1.Uri == rd2.Uri &&
		reflect.DeepEqual(rd1.Digest, rd2.Digest) &&
		bytes.Equal(rd1.Content, rd2.Content) &&
		rd1.DownloadLocation == rd2.DownloadLocation &&
		rd1.MediaType == rd2.MediaType
}
