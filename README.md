# jwt
json web token middleware for [vodka](http://github.com/insionng/vodka)



Use example:

```Go
package main

import (
	"fmt"
	"github.com/insionng/vodka"
	"github.com/vodka-contrib/jwt"
	"net/http"
	"net/http/httptest"
)

var (
	key = "AppSkey"
)

func NoJwtHandler(self *vodka.Context) error {
	return self.String(http.StatusOK, "NoJwtHandler")
}

func TokenHandler(self *vodka.Context) error {

	var claims = map[string]interface{}{}
	claims["username"] = "Insion"
	token, err := jwt.NewToken(key, claims)
	if err != nil {
		return err
	}
	// show the token use for test
	return self.String(http.StatusOK, "%s", token)
}

func JwtHandler(self *vodka.Context) error {
	Claims := jwt.Claims(self)
	return self.String(http.StatusOK, "{[Server Says]: Your name is %s.}", Claims["username"])
}

func main() {
	v := vodka.New()
	v.Any("/nojwt/", NoJwtHandler)
	v.Get("/token/", TokenHandler) //just for test

	// Restricted group
	r := v.Group("/jwt/")

	jwt.JWTContextKey = key
	r.Use(jwt.JWTAuther(jwt.Options{
		KeyFunc: func(ctx *vodka.Context) (string, error) {
			return jwt.JWTContextKey, nil
		},
	}))
	r.Any("", JwtHandler)

	//Server Side
	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://localhost:8000/nojwt/", nil)
	if err != nil {
		fmt.Println("nojwt errors:", err)
		return
	}
	v.ServeHTTP(recorder, req)
	fmt.Println("nojwt:", recorder.Body.String())
	//--------------------
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://localhost:8000/token/", nil)
	if err != nil {
		fmt.Println("gen token errors:", err)
		return
	}
	v.ServeHTTP(recorder, req)
	fmt.Printf("Server Gen Token:\n%v\n", recorder.Body.String())
	//--------------------
	//Client Side
	if token, err := jwt.NewToken(key, map[string]interface{}{"username": "Insion"}); err != nil {
		fmt.Printf("Client Gen Token Error:%v\n", err)
	} else {
		fmt.Printf("Client Gen Token:\n%v\n", token)
		req, err := http.NewRequest("GET", "http://localhost:8000/jwt/", nil)
		if err != nil {
			fmt.Println("http.NewRequest error:", err)
			return
		}
		req.Header.Add("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		v.ServeHTTP(recorder, req)
		fmt.Printf("Client Got %v.", recorder.Body.String())

	}

}

```


## QQ Group

Vodka/Echo Web 框架群号 242851426

