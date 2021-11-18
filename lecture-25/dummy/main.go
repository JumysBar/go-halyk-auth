package main

import (
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

type MySecurityServer struct {
	adminLogin    string
	adminPassword string
}

func extractCredential(ctx *fasthttp.RequestCtx) (login string, pass string) {
	return string(ctx.FormValue("login")), string(ctx.FormValue("password"))
}

func (s *MySecurityServer) CheckAuthMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		// Checking auth

		login, password := extractCredential(ctx)

		if login != s.adminLogin || password != s.adminPassword {
			log.Println("Invalid credentials!")
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			fmt.Fprintf(ctx, "Invalid credentials!")
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
