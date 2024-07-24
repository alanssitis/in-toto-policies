package policies

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	ita "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

func Verify(pd models.PolicyDocument) error {
	vm, err := parseFunctionaries(pd.Functionaries)
	if err != nil {
		return err
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	dir_entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	return verifyAttestations(pd.AttestationRules, dir_entries, vm)
}

func verifyAttestations(attestation_rules []*models.AttestationRule, dir_entries []fs.DirEntry, vm map[string]dsse.Verifier) error {
	for _, a := range attestation_rules {
		err := verifyAttestation(a, dir_entries, vm)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyAttestation(ar *models.AttestationRule, dir_entries []fs.DirEntry, vm map[string]dsse.Verifier) error {
	envelope, err := getEnvelope(dir_entries, ar.Name)
	if err != nil {
		return err
	}
	if envelope.PayloadType != "application/vnd.in-toto+json" {
		return errors.New("matched with an envelope that is not of type in-toto")
	}

	ev, err := buildEnvelopeVerifier(ar.AllowedFunctionaries, vm)
	if err != nil {
		return err
	}

	_, err = ev.Verify(context.TODO(), envelope)
	if err != nil {
		return err
	}

	statement, err := getStatement(envelope)
	if err != nil {
		return err
	}
	if ar.PredicateType != statement.PredicateType {
		return errors.New("predicate is not of the expected type")
	}

	// TODO: predicate matching work

	return nil
}

func getEnvelope(dir_entries []fs.DirEntry, name string) (*dsse.Envelope, error) {
	d, err := findMatchingFile(dir_entries, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(d.Name())
	if err != nil {
		return nil, err
	}

	var envelope dsse.Envelope
	err = json.Unmarshal(data, &envelope)
	if err != nil {
		return nil, err
	}

	return &envelope, nil
}

func findMatchingFile(dir_entries []fs.DirEntry, name string) (fs.DirEntry, error) {
	for _, de := range dir_entries {
		if strings.HasPrefix(de.Name(), name) && !de.IsDir() {
			return de, nil
		}
	}
	return nil, errors.New("could not find matching attestation file from current working directory")
}

func buildEnvelopeVerifier(allowed_functionaries []string, vm map[string]dsse.Verifier) (*dsse.EnvelopeVerifier, error) {
	vs := make([]dsse.Verifier, len(allowed_functionaries))
	for i, f := range allowed_functionaries {
		vs[i] = vm[f]
	}
	return dsse.NewEnvelopeVerifier(vs...)
}

func getStatement(envelope *dsse.Envelope) (*ita.Statement, error) {
	var statement ita.Statement
	data, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, err
	}
	err = protojson.Unmarshal(data, &statement)
	if err != nil {
		return nil, err
	}
	return &statement, nil
}
