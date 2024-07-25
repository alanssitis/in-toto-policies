package policies

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	ita "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
)

var sugar *zap.SugaredLogger

func Verify(pd models.PolicyDocument, fdir string, adir string) error {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := config.Build()
	if err != nil {
		return err
	}
	defer logger.Sync()
	sugar = logger.Sugar()
	defer func() {
		sugar = nil
	}()

	sugar.Infof("start policy verification")

	fdir, err = validateDir(fdir)
	if err != nil {
		return err
	}
	vm, err := parseFunctionaries(pd.Functionaries, fdir)
	if err != nil {
		sugar.Errorw("failed to parse functionaries",
			"error", err,
		)
		return err
	}

	adir, err = validateDir(adir)
	if err != nil {
		return err
	}
	dir_entries, err := os.ReadDir(adir)
	if err != nil {
		sugar.Errorw("failed to parse functionaries",
			"error", err,
		)
		return err
	}

	attestations := mapAttestations(adir, dir_entries)
	return verifyAttestationRules(pd.AttestationRules, attestations, vm)
}

func verifyAttestationRules(attestation_rules []*models.AttestationRule, attestations map[string]string, vm map[string]dsse.Verifier) error {
	sugar.Infof("start verifying attestation rules")

	for _, a := range attestation_rules {
		err := verifyAttestationRule(a, attestations, vm)
		if err != nil {
			sugar.Errorw("failed to verify attestation rule",
				"error", err,
			)
			return err
		}
	}
	return nil
}

func verifyAttestationRule(ar *models.AttestationRule, attestations map[string]string, vm map[string]dsse.Verifier) error {
	sugar.Infow("start verifying attestation rule",
		"name", ar.Name,
	)

	file := attestations[ar.Name]
	envelope, err := getEnvelope(file)
	if err != nil {
		sugar.Errorf("failed to get and parse envelope from attestation file")
		return err
	}
	if envelope.PayloadType != "application/vnd.in-toto+json" {
		sugar.Errorf("failed because file does not contain an in-toto typed envelope")
		return errors.New("matched with an envelope that is not of type in-toto")
	}

	ev, err := buildEnvelopeVerifier(ar.AllowedFunctionaries, vm)
	if err != nil {
		sugar.Errorf("failed to build envelope verifier from functionaries")
		return err
	}

	_, err = ev.Verify(context.TODO(), envelope)
	if err != nil {
		sugar.Errorf("failed to verify attestation from functionaries")
		return err
	}

	statement, err := getStatement(envelope)
	if err != nil {
		sugar.Errorf("failed to get and parse statement from envelope")
		return err
	}
	if ar.PredicateType != statement.PredicateType {
		sugar.Errorf("failed because actual predicate type differs from expected predicate type")
		return errors.New("predicate is not of the expected type")
	}

	// TODO: predicate matching work

	sugar.Infow("successfully verified attestation rule",
		"name", ar.Name,
		"attestationFileName", file,
	)

	return nil
}

func getEnvelope(f string) (*dsse.Envelope, error) {
	data, err := os.ReadFile(f)
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

func findMatchingFile(dir_entries []fs.DirEntry, name string, dir string) (string, error) {
	for _, de := range dir_entries {
		if strings.HasPrefix(de.Name(), name) && !de.IsDir() {
			return filepath.Join(dir, de.Name()), nil
		}
	}
	return "", errors.New("could not find matching attestation file")
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

func validateDir(dir string) (string, error) {
	if dir != "" {
		fi, err := os.Stat(dir)
		if err != nil {
			return dir, err
		}
		if !fi.IsDir() {
			return dir, errors.New("path passed is not a directory")
		}
		return dir, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		sugar.Errorw("failed to get current directory",
			"error", err,
		)
		return dir, err
	}
	return dir, nil
}

func mapAttestations(dir string, dir_entries []fs.DirEntry) map[string]string {
	ma := make(map[string]string)

	for _, de := range dir_entries {
		name := de.Name()
		if ext := filepath.Ext(name); ext != ".json" && ext != ".link" {
			continue
		}
		ma[name[:strings.IndexByte(name, '.')]] = filepath.Join(dir, name)
	}

	return ma
}
