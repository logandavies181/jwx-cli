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
var (
	jwkGenerateCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a JWK from a PEM Key file",
		RunE:  jwkGenerate,
	}

	// TODO: these probably aren't all strings
	use, alg, kid, x5u, x5c, x5t, x5ts256 string
	key_ops []string
)

func init() {
	jwkCmd.AddCommand(jwkGenerateCmd)

	jwkGenerateCmd.Flags().StringToStringVarP(&attr, "attr", "a", make(map[string]string), "List of arbitrary key-value pairs to add to the JWK e.g. 'sub=foo,iss=bar'")

	jwkGenerateCmd.Flags().StringVarP(&use, "use", "", "", "Key Usage")
	jwkGenerateCmd.Flags().StringSliceVarP(&key_ops, "ops", "", []string{} , "Key Ops")
	jwkGenerateCmd.Flags().StringVarP(&alg, "alg", "", "", "Algorithm")
	jwkGenerateCmd.Flags().StringVarP(&kid, "kid", "", "", "Key ID")
	jwkGenerateCmd.Flags().StringVarP(&x5u, "x5u", "", "", "X509 URL")
	jwkGenerateCmd.Flags().StringVarP(&x5c, "x5c", "", "", "X509 Cert Chain")
	jwkGenerateCmd.Flags().StringVarP(&x5t, "x5t", "", "", "X509 Thumbprint")
	jwkGenerateCmd.Flags().StringVarP(&x5ts256, "x5ts256", "", "", "X509 Thumbprint SHA256")

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

	jwkKeyInterface, err = addHeaders(jwkKeyInterface)
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

func addHeaders(j jwk.Key) (jwk.Key, error) {
	for k, v := range attr {
		setWrapper(k, v, j)
	}

	// prefer standard headers over arbitrary key/value pairs
	if use != "" {
		setWrapper("use", use, j)
	}
	if len(key_ops) != 0 {
		setWrapper("key_ops", key_ops, j)
	}
	if alg != "" {
		setWrapper("alg", alg, j)
	}
	if kid != "" {
		setWrapper("kid", kid, j)
	}
	if x5u != "" {
		setWrapper("x5u", x5u, j)
	}
	// TODO: this should probably be a slice
	if x5c != "" {
		setWrapper("x5c", x5c, j)
	}
	if x5t != "" {
		setWrapper("x5t", x5t, j)
	}
	if x5ts256 != "" {
		setWrapper("x5t#S256", x5ts256, j)
	}

	return j, nil
}

