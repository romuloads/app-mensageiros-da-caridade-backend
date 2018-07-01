package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/prest/adapters/postgres"
	"github.com/prest/cmd"
	"github.com/prest/config"
	_ "github.com/adelowo/muxlist"
	"github.com/prest/middlewares"
	"github.com/auth0/go-jwt-middleware"
	"fmt"
)

// Fazer pullRequest Prest Issue: middleware: whitelist endpoint #277
const JWT_WHITELIST = "/auth"

// Body data structure used to receive request
type Body struct {
	Username string
	Password string
}

// Auth data structure used to return authentication token
type Auth struct {
	Token string
}

type AuthError struct {
	Error string
}

func main() {
	// start pREST config
	config.Load()

	// pREST Postgres
	postgres.Load()

	// pREST routes
	//r := router.Get()

	// Common middleware this application
	n := middlewares.GetApp()
	n.UseFunc(CustomMiddleware)
	//n.Use(middlewares.JwtMiddleware(config.PrestConf.JWTKey,config.PrestConf.JWTAlgo))

	// Call pREST cmd
	cmd.Execute()

}

// tokenGenerate return token JWT (simulating authentication)
func tokenGenerate(Username string) (signedToken string, err error) {
	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 1000).Unix(),
		Issuer:    Username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = token.SignedString([]byte(config.PrestConf.JWTKey))
	return
}

type Person struct {
	Id       int
	Name     string
	Email    string
	Password string
	Role     string
}

func CustomMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	fmt.Println(r.RequestURI)

	//retorno := sc.Bytes()
	//err := binary.Read(retorno, binary.BigEndian, &pessoa)

	if r.RequestURI == JWT_WHITELIST {
		person := Person{}
		email := r.Header.Get("email");
		//userName := r.Header.Get("userName");
		passWord := r.Header.Get("password");
		if email == "" || passWord == "" {
			//err := AuthError{ Error: "Preencha usuário e senha!" }
			http.Error(w, "Preencha usuário e senha!", http.StatusBadRequest)
		}
		runQuery := config.PrestConf.Adapter.Query
		sqlSelect := `SELECT id, name, email, password, role FROM person WHERE email = $1`
		var values []interface{}
		values = append(values, email)
		sc := runQuery(sqlSelect, values...)
		if sc.Err() != nil {
			http.Error(w, sc.Err().Error(), http.StatusBadRequest)
			return
		}
		quant, err := sc.Scan(&person)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		if quant >= 1 && email == person.Email && passWord == person.Password {
			tokenString, err := tokenGenerate(person.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			auth := Auth{
				Token: tokenString,
			}
			w.WriteHeader(http.StatusOK)
			ret, _ := json.Marshal(auth)
			w.Write(ret)
		} else {
			http.Error(w, "Usuário ou senha incorreto!", http.StatusBadRequest)
		}
	} else {

		jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				return []byte(config.PrestConf.JWTKey), nil
			},
			SigningMethod: jwt.GetSigningMethod(config.PrestConf.JWTAlgo),
		})
		err := jwtMiddleware.CheckJWT(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		if next != nil {
			next(w, r)
		}
	}

}
