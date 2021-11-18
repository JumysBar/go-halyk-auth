package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/valyala/fasthttp"
)

type MySecurityServer struct {
	adminLogin    string
	adminPassword string
}

func extractCredential(ctx *fasthttp.RequestCtx) (login string, pass string, err error) {
	header := string(ctx.Request.Header.Peek("Authorization"))
	if header == "" {
		err = fmt.Errorf("Authorization header not found")
		return
	}
	parsedHeader := strings.Split(header, " ")
	if len(parsedHeader) != 2 || parsedHeader[0] != "Basic" {
		err = fmt.Errorf("Invalid authorization header")
		return
	}

	// Плохо
	rawCredentials, _ := base64.StdEncoding.DecodeString(parsedHeader[1])
	credentials := strings.Split(string(rawCredentials), ":")

	// Оч плохо
	login = credentials[0]
	pass = credentials[1]
	return
}

func (s *MySecurityServer) CheckAuthMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		// Checking auth

		login, password, err := extractCredential(ctx)
		if err != nil {
			log.Printf("Extract error: %v", err)
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.Response.Header.Add("WWW-Authenticate", "Basic")
			return
		}

		if login != s.adminLogin || password != s.adminPassword {
			log.Println("Invalid credentials!")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.Response.Header.Add("WWW-Authenticate", "Basic")
			return
		}

		// authorization success

		ctx.SetUserValue("login", login)

		next(ctx)
	}
}

func (s *MySecurityServer) MainHandler(ctx *fasthttp.RequestCtx) {
	user := ctx.Value("login").(string)

	log.Printf("User %s sent request", user)

	fmt.Fprintf(ctx, "Super security information")
	return
}

func main() {

	s := &MySecurityServer{
		adminLogin:    "admin",
		adminPassword: "qwerty123",
	}

	fasthttp.ListenAndServe(":8080", s.CheckAuthMiddleware(s.MainHandler))

}
