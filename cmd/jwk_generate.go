// This file is for generating jwks. It is not generated itself :)
package cmd

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/cobra"
)

// crytpo.PublicKey and crytpo.PrivateKey are both aliases for empty interface...
type cryptoKey interface{}

const (
	EC_PRIVATE_KEY_HEADER  = "EC PRIVATE KEY"
	PKCS8_HEADER           = "PRIVATE KEY"
	PUBLIC_KEY_HEADER      = "PUBLIC KEY"
	RSA_PRIVATE_KEY_HEADER = "RSA PRIVATE KEY"
)

// generateCmd represents the generate command
var jwkGenerateCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a JWK from a PEM Key file",
	RunE:  jwkGenerate,
}

func init() {
	jwkCmd.AddCommand(jwkGenerateCmd)

	jwkGenerateCmd.Flags().BoolVarP(&symmetric, "symmetric-key", "", false, "Indicates the key is a symmetric key")
}

func jwkGenerate(_ *cobra.Command, _ []string) error {
	key, err := getKey()
	if err != nil {
		return err
	}

	var jwkKeyInterface jwk.Key
	switch v := key.(type) {
	case crypto.PrivateKey:
		jwkKeyInterface, err = jwk.New(v)

	case crypto.PublicKey:
		jwkKeyInterface, err = jwk.New(v)
	default:
		return errors.New("Could not determine key type")
	}
	// Check the err from the switch statement
	if err != nil {
		return err
	}

	m, err := jwkKeyInterface.AsMap(context.TODO())
	if err != nil {
		return err
	}
	jwkJSON, err := json.Marshal(m)
	if err != nil {
		return err
	}

	fmt.Println(string(jwkJSON))

	return nil
}

func getKey() (cryptoKey, error) {
	// Check opt and read file
	if keyFile == "" {
		return nil, errors.New("Must supply a key file")
	}
	keyDat, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	// Parse pem data
	keyBlock, _ := pem.Decode(keyDat)
	if keyBlock == nil {
		if !symmetric {
			return nil, errors.New("No valid key found in PEM")
		} else {
			// Warning! This includes \n at the end of file.
			// TODO: check if this is normal
			return keyDat, nil
		}
	}

	var key cryptoKey
	switch keyBlock.Type {
	// TODO: Add DSA!!
	case EC_PRIVATE_KEY_HEADER:
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case PKCS8_HEADER:
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case PUBLIC_KEY_HEADER:
		key, err = x509.ParsePKIXPublicKey(keyBlock.Bytes)
	case RSA_PRIVATE_KEY_HEADER:
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("Failed to parse key file")
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}
