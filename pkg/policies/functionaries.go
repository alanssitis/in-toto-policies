package policies

import (
	"errors"

	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

func parseFunctionaries(functionaries []*models.Functionary) (map[string]dsse.Verifier, error) {
	vs := make(map[string]dsse.Verifier, len(functionaries))
	for _, f := range functionaries {
		v, err := loadPublicKeyVerifier(f.PublicKeyPath, f.Scheme)
		if err != nil {
			return nil, err
		}
		vs[f.Name] = v
	}
	return vs, nil
}

func loadPublicKeyVerifier(publicKeyPath string, scheme string) (dsse.Verifier, error) {
	switch scheme {
	case "rsa-pss":
		rsa, err := signerverifier.LoadRSAPSSKeyFromFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(rsa)
	case "ecdsa":
		ecdsa, err := signerverifier.LoadECDSAKeyFromFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewECDSASignerVerifierFromSSLibKey(ecdsa)
	case "ed25519":
		ed25519, err := signerverifier.LoadED25519KeyFromFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewED25519SignerVerifierFromSSLibKey(ed25519)
	default:
		return nil, errors.New("Unrecognized scheme")
	}
}
