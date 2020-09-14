package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/spf13/cobra"
)

var (
	jwtReadCmd = &cobra.Command{
		Use:   "read",
		Short: "Print the contents of a signed JWT in human readable form",
		RunE:  jwtRead,
	}
)

func init() {
	jwtCmd.AddCommand(jwtReadCmd)
}

func jwtRead(_ *cobra.Command, args []string) error {
	var jwtDat []byte

	if len(args) == 0 {
		pipedDat, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		jwtDat = pipedDat
	} else {
		fileDat, err := ioutil.ReadFile(args[0])
		if err != nil {
			return err
		}
		jwtDat = fileDat
	}

	parts := strings.Split(string(jwtDat), ".")
	if len(parts) != 3 {
		return errors.New("Loaded JWT data not in compact form")
	}

	header, err := base64url.Decode(parts[0])
	if err != nil {
		return err
	}
	payload, err := base64url.Decode(parts[1])
	if err != nil {
		return err
	}

	fmt.Println(string(header))
	fmt.Println(string(payload))
	fmt.Print(parts[2])

	return nil
}
