package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/insionng/vodka"
)

func NoJwtHandler(self *vodka.Context) error {
	return self.String(http.StatusOK, "NoJwtHandler")
}

func JwtHandler(self *vodka.Context) error {
	Claims := Claims(self)
	fmt.Printf("Got token %v by JwtHandler. ", Claims["token"] == "insion's-Token")
	return self.String(http.StatusOK, "JwtHandler")

}

func TokenHandler(self *vodka.Context) error {

	var claims = map[string]interface{}{}
	claims["token"] = "insion's-Token"
	token, err := NewToken(JWTContextKey, claims)
	if err != nil {
		return err
	}
	// show the token use for test
	return self.String(http.StatusOK, "%s", token)
}

func TestJwt(t *testing.T) {
	v := vodka.New()
	v.Get("/nojwt/", NoJwtHandler)
	v.Get("/token/", TokenHandler)

	// Restricted group
	r := v.Group("/jwt/")
	r.Use(JWTAuther(Options{
		KeyFunc: func(ctx *vodka.Context) (string, error) {
			return JWTContextKey, nil
		},
	}))
	r.Any("", JwtHandler)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://localhost:8000/token/", nil)
	if err != nil {
		t.Error(err)
	}

	v.ServeHTTP(recorder, req)
	token := recorder.Body.String()

	if len(token) == 0 {
		t.Error("len(token) == 0")
	} else {
		fmt.Println("token:", token)
	}

	//---------------------------------
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://localhost:8000/jwt/", nil)
	if err != nil {
		t.Error(err)
	}

	req.Header.Add("Authorization", "Bearer "+token)

	v.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	expect(t, recorder.Body.String(), "JwtHandler")
	//---------------------------------

	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://localhost:8000/nojwt/", nil)
	if err != nil {
		t.Error(err)
	}

	v.ServeHTTP(recorder, req)

	expect(t, recorder.Code, http.StatusOK)
	expect(t, recorder.Body.String(), "NoJwtHandler")

}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
