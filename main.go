package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
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
	tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// Don't forget to validate the alg is what you expect:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		//hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secretKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied! Please check the access token."))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		response := make(map[string]string)
		//response["user"] = claims["username"]
		response["time"] = time.Now().String()
		response["user"] = claims["username"].(string)
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
	}
}

func main() {

}
