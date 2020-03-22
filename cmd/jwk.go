package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// jwkCmd represents the jwk command
var jwkCmd = &cobra.Command{
	Use:   "jwk",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("jwk called")
	},
}

func init() {
	rootCmd.AddCommand(jwkCmd)
}
