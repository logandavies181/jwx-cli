package cmd

import (
//	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

type internalJWK struct {
	jwks *jwk.Set
}

// Get JWK from either file or URL
func getJWK() (*internalJWK, error) {
	if jwkURL != "" && jwkFile != "" {
		return nil, &jwxCliError{reason: "JWK must be from file or from URL. Not both"}
	}

	if jwkURL != "" {
		return nil, &jwxCliError{reason: "Not implemented"}
	}
	if jwkFile != "" {
		return readJWKFromFile(jwkFile)
	}
	return nil, &jwxCliError{reason: "Not implemented"}
}

func readJWKFromFile(filename string) (*internalJWK, error) {
	dat, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	jwkSet, err := jwk.Parse(dat)
	if err != nil {
		return nil, err
	}
	return &internalJWK{jwks: jwkSet}, nil
}
