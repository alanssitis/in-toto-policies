package policies

import (
	"errors"
	"path/filepath"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

func parseFunctionaries(functionaries []*models.Functionary, dir string) (map[string]dsse.Verifier, error) {
	sugar.Infof("parsing functionaries")
	vs := make(map[string]dsse.Verifier, len(functionaries))
	for _, f := range functionaries {
		v, err := loadPublicKeyVerifier(filepath.Join(dir, f.PublicKeyPath), f.Scheme)
		if err != nil {
			return nil, err
		}
		keyId, err := v.KeyID()
		if err != nil {
			return nil, err
		}
		sugar.Infow("added functionary",
			"name", f.Name,
			"keyID", keyId,
		)
		vs[f.Name] = v
	}
	return vs, nil
}

func loadPublicKeyVerifier(public_key_path string, scheme string) (dsse.Verifier, error) {
	switch scheme {
	case "rsa-pss":
		rsa, err := signerverifier.LoadRSAPSSKeyFromFile(public_key_path)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(rsa)
	case "ecdsa":
		ecdsa, err := signerverifier.LoadECDSAKeyFromFile(public_key_path)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewECDSASignerVerifierFromSSLibKey(ecdsa)
	case "ed25519":
		ed25519, err := signerverifier.LoadED25519KeyFromFile(public_key_path)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewED25519SignerVerifierFromSSLibKey(ed25519)
	default:
		return nil, errors.New("unrecognized scheme")
	}
}
