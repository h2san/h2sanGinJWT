package h2sanGinJWT

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var defaultSignKey = "h2san.gin.jwt"

const DefaultGinJWTKey = "defaultGinJWTKey"
const DefaultGinJSONKey = "defaultGinJSONKey"

//GinJWT gin web  framework jwt middlewire
func GinJWT(obj interface{}, signKey string) gin.HandlerFunc {
	defaultSignKey = signKey
	return func(c *gin.Context) {
		var tokenString string
		if c.GetHeader("Content-Type") == "application/json" {
			b, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"code":   -1,
					"errMsg": "read request body err",
					"data":   "",
				})
				c.Abort()
				return
			}
			reqJSON := make(map[string]interface{})
			err = json.Unmarshal(b, &reqJSON)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"code":   -1,
					"errMsg": "read json data not invalid",
					"data":   "",
				})
				c.Abort()
				return
			}
			if val, ok := reqJSON["token"]; ok {
				if sval, ok := val.(string); ok {
					tokenString = sval
				}
			}
			c.Set(DefaultGinJSONKey, b)
		}

		// Parse the token
		token, err := jwt.ParseWithClaims(tokenString, &GinClaims{}, func(token *jwt.Token) (interface{}, error) {
			// since we only use the one private key to sign the tokens,
			// we also only use its public counter part to verify
			return []byte(defaultSignKey), nil
		})
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code":   -1,
				"errMsg": "token invalid" + err.Error(),
				"data":   "",
			})
			c.Abort()
			return
		}

		claims := token.Claims.(*GinClaims)
		c.Set(DefaultGinJWTKey, claims.Obj)
		c.Next()
	}

}

type GinClaims struct {
	*jwt.StandardClaims
	Obj interface{}
}

func CreateToken(obj interface{}) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("HS256"))
	t.Claims = &GinClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 100).Unix(),
		},
		obj,
	}
	return t.SignedString([]byte(defaultSignKey))
}
