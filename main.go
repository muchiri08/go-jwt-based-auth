package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"time"
)

var secretKey = []byte(os.Getenv("SESSION_SECRET"))
var users = map[string]string{"kennedy": "12345", "admin": "password"}

// Response is a representation of JSON response for JWT
type Response struct {
	Token  string `json:"token"`
	Status string `json:"status"`
}

// HealthcheckHandler return the date and time
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	response := make(map[string]string)
	response["time"] = time.Now().String()
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)

}

// LoginHandler validates the user credentials
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	originalPassword, ok := users[username]
	if !ok {
		http.Error(w, "User is not found!", http.StatusUnauthorized)
		return
	}
	if originalPassword == password {
		//create a claim map
		claims := jwt.MapClaims{
			"username":  username,
			"ExpiresAt": 15000,
			"IssuedAt":  time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(err.Error()))
		}
		response := Response{
			Token:  tokenString,
			Status: "success",
		}
		responseJSON, _ := json.Marshal(response)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(responseJSON)

	} else {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
}

func AnotherHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	w.Write([]byte(fmt.Sprintf("Hello %s and welcome.", name)))
}

func validateJWTMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//tokenString := r.Header.Get("access_token") -> This can also be used to get the token string from the req header
		tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)
		//validating jwt
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secretKey, nil
		})
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Permission Denied!"))
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Permission denied!"))
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", getTokenHandler)
	r.HandleFunc("/getToken", getTokenHandler)

	req := r.PathPrefix("/api").Subrouter()
	req.HandleFunc("/welcome/{name}", AnotherHandler)
	req.HandleFunc("/healthcheck", HealthcheckHandler).Methods("GET")
	req.Use(validateJWTMiddleware)

	server := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:8000",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("server up and running...")
	log.Fatal(server.ListenAndServe())

}
