package jwt

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/insionng/vodka"
)

var (
	Bearer        = "Bearer"
	JWTContextKey = "JWTContextKey"
)

type Options struct {
	KeyFunc        func(*vodka.Context) (string, error)
	CheckWebSocket bool
}

func Claims(value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case *vodka.Context:
		return v.Get(JWTContextKey).(map[string]interface{})
	default:
		return nil
	}
}

func prepareOptions(opts []Options) Options {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.KeyFunc == nil {
		opt.KeyFunc = func(ctx *vodka.Context) (string, error) {
			return JWTContextKey, nil
		}
	}

	return opt
}

// A JSON Web Token middleware
func JWTAuther(opts ...Options) vodka.HandlerFunc {
	opt := prepareOptions(opts)
	return func(ctx *vodka.Context) error {
		if !opt.CheckWebSocket {
			// Skip WebSocket
			if (ctx.Request().Header.Get(vodka.Upgrade)) == vodka.WebSocket {
				return nil
			}
		}

		key, err := opt.KeyFunc(ctx)
		if err != nil {
			return err
		}

		auth := ctx.Request().Header.Get("Authorization")
		l := len(Bearer)
		he := vodka.NewHTTPError(http.StatusUnauthorized)
		if len(auth) > l+1 && auth[:l] == Bearer {
			t, err := jwt.Parse(auth[l+1:], func(token *jwt.Token) (interface{}, error) {
				// Always check the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				// Return the key for validation
				return []byte(key), nil
			})

			if err == nil && t.Valid {
				// Store token claims
				ctx.Set(JWTContextKey, t.Claims)
				return nil
			}
		}

		return he

	}
}

func NewToken(key string, claims ...map[string]interface{}) (string, error) {
	// New web token.
	token := jwt.New(jwt.SigningMethodHS256)

	// Set a header and a claim
	token.Header["typ"] = "JWT"
	token.Claims["exp"] = time.Now().Add(time.Second * 60).Unix()

	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Claims[k] = v
		}
	}

	// Generate encoded token
	return token.SignedString([]byte(key))
}
