package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path"

	"github.com/alanssitis/in-toto-policies/pkg/policies"
	"github.com/alanssitis/in-toto-policies/pkg/policies/models"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

var (
	fdir string
	adir string
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify POLICY_FILE",
	Short: "Verify the in-toto policy",
	Args:  cobra.ExactArgs(1),
	RunE:  verify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	verifyCmd.Flags().StringVarP(&fdir, "functionary-directory", "f", "", "Relative directory to get functionary information")
	verifyCmd.Flags().StringVarP(&adir, "attestation-directory", "a", "", "Directory to search all attestations")
}

func verify(cmd *cobra.Command, args []string) error {
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}

	pd := models.PolicyDocument{}
	policy_ext := path.Ext(args[0])

	switch {
	case policy_ext == ".yml" || policy_ext == ".yaml":
		err = yaml.Unmarshal(raw, &pd)
		if err != nil {
			return err
		}
	case policy_ext == ".json":
		err = json.Unmarshal(raw, &pd)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported file extension for test policy file")
	}

	return policies.Verify(pd, fdir, adir)
}
