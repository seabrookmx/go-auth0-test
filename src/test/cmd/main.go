package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var pemCache = make(map[string]string)

func getPemCert(jwksUri string, token *jwt.Token) (string, error) {
	// This is a slightly modified version of the Auth0 example, which will
	// cache the JWKS cert based on the kid. Links below:
	// https://auth0.com/docs/quickstart/backend/golang/01-authorization#create-a-middleware-to-validate-access-tokens
	// https://github.com/auth0-samples/auth0-golang-api-samples/blob/master/01-Authorization-RS256/main.go

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", errors.New("Invalid token")
	}

	elem, ok := pemCache[kid]
	if ok {
		// TODO: removeme
		fmt.Println("Returned a cached cert")
		// End TODO
		return elem, nil
	}

	cert := ""
	resp, err := http.Get(jwksUri)

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if kid == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	pemCache[kid] = cert

	// TODO: removeme
	fmt.Println("Got a new cert and cached it")
	// End TODO
	return cert, nil
}

func main() {
	fmt.Println("Hello World :)")

	// TODO: bad hard coded config - should be taken from environment variables
	port := 8066
	audience := "https://api.dummy.com"
	auth0Domain := "domain.auth0.com"
	jwksUri := "https://domain.auth0.com/.well-known/jwks.json"
	// End TODO

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
			if !checkAud {
				return token, errors.New("Invalid audience.")
			}
			// Verify 'iss' claim
			iss := "https://" + auth0Domain + "/"
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("Invalid issuer.")
			}

			cert, err := getPemCert(jwksUri, token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	root := mux.NewRouter()

	root.PathPrefix("/api").Handler(jwtMiddleware.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// dummy route with auth
			io.WriteString(w, "foobar!")
		})),
	)

	root.PathPrefix("/health").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// dummy route wout auth
		io.WriteString(w, "OK")
	})

	http.Handle("/", root)

	fmt.Printf("Listening on %d\n", port)
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}
