package cmd

import (
	//"encoding/json"
	//"fmt"
	//"io/ioutil"
	//"os"

	//"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	//"github.com/lestrrat-go/jwx/jws"
	//"github.com/lestrrat-go/jwx/jwt"
)

type internalJWK struct {
	jwk jwk.Key
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
		return nil, &jwxCliError{reason: "Not implemented"}
	}
	return nil, &jwxCliError{reason: "Not implemented"}
}
