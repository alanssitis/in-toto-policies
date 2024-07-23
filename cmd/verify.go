package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/alanssitis/in-toto-policies/pkg/policies"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
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
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func verify(cmd *cobra.Command, args []string) error {

	raw, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	pd := policies.PolicyDocument{}
	policy_ext := path.Ext(args[0])

	switch {
	case policy_ext == ".yml" || policy_ext == ".yaml":
		err = yaml.Unmarshal(raw, &pd)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	case policy_ext == ".json":
		err = json.Unmarshal(raw, &pd)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	default:
		log.Fatalf("error: unsupported file extension for policy (%s)", policy_ext)
	}

	return nil
}
