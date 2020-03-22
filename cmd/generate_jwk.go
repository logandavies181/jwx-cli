package cmd

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var jwkGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		jwkGenerateMain()
	},
}

func init() {
	jwkCmd.AddCommand(jwkGenerateCmd)

}

func jwkGenerateMain() {
	// TODO: allow reading from private key

	privateKey, err := getKey()
	if err != nil {
		exit(err)
	}

	jwkKeyInterface, err := jwk.New(privateKey.privateKey)
	if err != nil {
		exit(err)
	}

	jwkKey := jwkKeyInterface.(*jwk.RSAPrivateKey)

	jwkJSON, err := jwkKey.MarshalJSON()
	if err != nil {
		exit(err)
	}

	fmt.Println(string(jwkJSON))
}
