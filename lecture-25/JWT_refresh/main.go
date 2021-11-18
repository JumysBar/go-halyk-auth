package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/buaazp/fasthttprouter"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/valyala/fasthttp"
)

type MySecurityServer struct {
	adminID       int64
	adminLogin    string
	adminPassword string

	accessSecret  string
	refreshSecret string

	redisConn *redis.Client

	accessTtl  time.Duration
	refreshTtl time.Duration
}

func extractCredential(ctx *fasthttp.RequestCtx) (login string, pass string) {
	return string(ctx.FormValue("login")), string(ctx.FormValue("password"))
}

func extractToken(ctx *fasthttp.RequestCtx) (token string, err error) {
	header := string(ctx.Request.Header.Peek("Authorization"))
	if header == "" {
		err = fmt.Errorf("Authorization header not found")
		return
	}
	parsedHeader := strings.Split(header, " ")
	if len(parsedHeader) != 2 || parsedHeader[0] != "Bearer" {
		err = fmt.Errorf("Invalid authorization header")
		return
	}

	token = parsedHeader[1]
	return
}

func (s *MySecurityServer) parseToken(token string, isAccess bool) (int64, error) {
	JWTToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Failed to extract token metadata, unexpected signing method: %v", token.Header["alg"])
		}
		if isAccess {
			return []byte(s.accessSecret), nil
		}
		return []byte(s.refreshSecret), nil
	})

	if err != nil {
		return 0, err
	}

	claims, ok := JWTToken.Claims.(jwt.MapClaims)

	var userId float64

	if ok && JWTToken.Valid {
		userId, ok = claims["id"].(float64)
		if !ok {
			return 0, fmt.Errorf("Field id not found")
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			return 0, fmt.Errorf("Field exp not found")
		}

		expiredTime := time.Unix(int64(exp), 0)
		log.Printf("Expired: %v", expiredTime)
		if time.Now().After(expiredTime) {
			return 0, fmt.Errorf("Token expired")
		}
		return int64(userId), nil
	}

	return 0, fmt.Errorf("Invalid token")
}

func (s *MySecurityServer) findToken(id int64, token string) bool {
	key := fmt.Sprintf("user:%d", s.adminID)

	value, err := s.redisConn.Get(key).Result()
	if err != nil {
		return false
	}

	return token == value
}

func (s *MySecurityServer) insertToken(token string) error {
	key := fmt.Sprintf("user:%d", s.adminID)

	return s.redisConn.Set(key, token, s.refreshTtl).Err()
}

func (s *MySecurityServer) ExampleLoginPage(ctx *fasthttp.RequestCtx) {
	// Static web page with login/password page
	ctx.Response.Header.SetContentType("text/html")
	fmt.Fprintf(ctx, `
<html>
<head>
</head>
<body>
<form action="/login" method="post">
	<label for="login">Login:</label> <br>
	<input type="text" id="login" name="login"> <br>
	<label for="password">Password:</label> <br>
	<input type="text" id="password" name="password"> <br>
	<input type="submit" value="Sign in">
</form>
</body>
</html>
`)
}

func (s *MySecurityServer) GenerateAndSendTokens(ctx *fasthttp.RequestCtx) {
	// Create JWT access and refresh token and send to client
	accessTokenExp := time.Now().Add(s.accessTtl).Unix()

	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["id"] = s.adminID
	accessTokenClaims["iat"] = time.Now().Unix()
	accessTokenClaims["exp"] = accessTokenExp
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessSignedToken, err := accessToken.SignedString([]byte(s.accessSecret))
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "Coundn't create token. Error: %v", err)
		return
	}

	refreshTokenExp := time.Now().Add(s.refreshTtl).Unix()
	refreshTokenClaims := jwt.MapClaims{}
	refreshTokenClaims["id"] = s.adminID
	refreshTokenClaims["iat"] = time.Now().Unix()
	refreshTokenClaims["exp"] = refreshTokenExp
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

	refreshSignedToken, err := refreshToken.SignedString([]byte(s.refreshSecret))
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "Coundn't create token. Error: %v", err)
		return
	}

	if err := s.insertToken(refreshSignedToken); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "Coundn't insert token in redis. Error: %v", err)
		return
	}

	fmt.Fprintf(ctx, "Access token: %s\nRefresh token: %s", accessSignedToken, refreshSignedToken)
}

func (s *MySecurityServer) LoginHandler(ctx *fasthttp.RequestCtx) {
	login, password := extractCredential(ctx)

	if login != s.adminLogin || password != s.adminPassword {
		log.Println("Invalid credentials!")
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		fmt.Fprintf(ctx, "Invalid credentials!")
		return
	}

	s.GenerateAndSendTokens(ctx)
}

func (s *MySecurityServer) UpdateHandler(ctx *fasthttp.RequestCtx) {
	refreshToken := string(ctx.FormValue("refresh"))

	//checking update token
	id, err := s.parseToken(refreshToken, false)
	if err != nil {
		log.Printf("Parse refresh token error: %v", err)
		ctx.SetStatusCode(fasthttp.StatusMovedPermanently)
		ctx.Response.Header.Add("Location", "/login")
		return
	}

	// find token in Redis
	ok := s.findToken(id, refreshToken)
	if !ok {
		log.Printf("Getting refresh token failed")
		ctx.SetStatusCode(fasthttp.StatusMovedPermanently)
		ctx.Response.Header.Add("Location", "/login")
		return
	}

	s.GenerateAndSendTokens(ctx)
}

func (s *MySecurityServer) CheckAuthMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	r := fasthttprouter.New()
	r.GET("/login", s.ExampleLoginPage)
	r.POST("/login", s.LoginHandler)
	r.POST("/update", s.UpdateHandler)
	r.GET("/", func(ctx *fasthttp.RequestCtx) {
		// Checking auth

		token, err := extractToken(ctx)
		if err != nil {
			log.Printf("Extract access token error: %v", err)
			ctx.SetStatusCode(fasthttp.StatusMovedPermanently)
			ctx.Response.Header.Add("Location", "/login")
			return
		}

		id, err := s.parseToken(token, true)
		if err != nil {
			log.Printf("Parse access token error: %v", err)
			ctx.SetStatusCode(fasthttp.StatusMovedPermanently)
			ctx.Response.Header.Add("Location", "/login")
			return
		}

		// authorization success

		ctx.SetUserValue("userID", id)

		next(ctx)
	})

	return r.Handler
}

func (s *MySecurityServer) MainHandler(ctx *fasthttp.RequestCtx) {
	user := ctx.Value("userID").(int64)

	log.Printf("User %d sent request", user)

	fmt.Fprintf(ctx, "Super security information")
	return
}

func main() {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	pong, err := client.Ping().Result()
	if err != nil {
		log.Fatalf("Ping error: %v", err)
	}

	log.Println(pong)

	s := &MySecurityServer{
		adminID:       1,
		adminLogin:    "admin",
		adminPassword: "qwerty123",

		accessSecret:  "18DbJX9NR0WApJtB9OgmQkdlmHLwaHpK",
		refreshSecret: "ICdzotFuzFduNeFhWvg4cieOTWyFccIr",

		redisConn:  client,
		accessTtl:  20 * time.Second,
		refreshTtl: 10 * time.Minute,
	}

	fasthttp.ListenAndServe(":8080", s.CheckAuthMiddleware(s.MainHandler))

}
