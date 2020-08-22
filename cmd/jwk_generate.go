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
	PRIVATE_KEY_HEADER = "RSA PRIVATE KEY"
	PUBLIC_KEY_HEADER  = "PUBLIC KEY"
)

// generateCmd represents the generate command
var jwkGenerateCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a JWK from a PEM Key file",
	RunE:  jwkGenerate,
}

func init() {
	jwkCmd.AddCommand(jwkGenerateCmd)
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

	/*
		// We technically don't know the type of the returned key until we use a switch
		var jwkJSON []byte
		switch v := jwkKeyInterface.(type) {
		case jwk.RSAPrivateKey:
			jwkJSON, err = v.MarshalJSON()
		case jwk.RSAPublicKey:
			jwkJSON, err = v.MarshalJSON()
		default:
			return errors.New("Unexpected error with generated JWK")
		}
		// Check the err from the switch statement
		if err != nil {
			return err
		}
	*/
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
		return nil, errors.New("No valid private key found in PEM")
	}
	var pemKey cryptoKey
	if keyBlock.Type == PRIVATE_KEY_HEADER {
		privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pemKey = privateKey
	} else if keyBlock.Type == PUBLIC_KEY_HEADER {
		publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pemKey = publicKey
	} else {
		return nil, errors.New("Failed to parse key file")
	}

	return pemKey, nil
}
