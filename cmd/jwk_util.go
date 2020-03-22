package cmd

import (
        "encoding/json"
        "fmt"
        "io/ioutil"
        "os"

        //"github.com/lestrrat-go/jwx/jwa"
        "github.com/lestrrat-go/jwx/jwk"
        //"github.com/lestrrat-go/jwx/jws"
        //"github.com/lestrrat-go/jwx/jwt"
)

type internalJWK struct {
	jwk jwk.Key
}

// Get JWK from either file or URL
func getJWK() (*internalJwk, error) {
	if url != "" && jwkFile != nil {
		return nil, &jwxCliError{reason: "URL must be from or from URL. Not both"}
	}

	if url != "" {
		return nil, &jwxCliError{reason: "Not implemented"}
	}
	if jwkFile := nil {
		
	}
}
