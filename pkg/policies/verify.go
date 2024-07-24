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
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	return verifyAttestations(pd.Attestations, dirEntries, vm)
}

func verifyAttestations(attestations []*models.Attestation, dirEntries []fs.DirEntry, vm map[string]dsse.Verifier) error {
	for _, a := range attestations {
		err := verifyAttestation(a, dirEntries, vm)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyAttestation(a *models.Attestation, dirEntries []fs.DirEntry, vm map[string]dsse.Verifier) error {
	envelope, err := getEnvelope(dirEntries, a.Name)
	if err != nil {
		return err
	}
	if envelope.PayloadType != "application/vnd.in-toto+json" {
		return errors.New("matched with an envelope that is not of type in-toto")
	}

	ev, err := buildEnvelopeVerifier(a.AllowedFunctionaries, vm)
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
	if a.PredicateType != statement.PredicateType {
		return errors.New("predicate is not of the expected type")
	}

	// TODO: predicate matching work

	return nil
}

func getEnvelope(dirEntries []fs.DirEntry, name string) (*dsse.Envelope, error) {
	d, err := findMatchingFile(dirEntries, name)
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

func findMatchingFile(dirEntries []fs.DirEntry, name string) (fs.DirEntry, error) {
	for _, d := range dirEntries {
		if strings.HasPrefix(d.Name(), name) && !d.IsDir() {
			return d, nil
		}
	}
	return nil, errors.New("could not find matching attestation file from current working directory")
}

func buildEnvelopeVerifier(allowedFunctionaries []string, vm map[string]dsse.Verifier) (*dsse.EnvelopeVerifier, error) {
	vs := make([]dsse.Verifier, len(allowedFunctionaries))
	for i, f := range allowedFunctionaries {
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
