package main

import (
	"log"
	"net/url"
	"strings"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type MyServer struct {
	oauthConf        *oauth2.Config
	oauthStateString string
}

func (s *MyServer) MainPage(ctx *fasthttp.RequestCtx) {
	log.Println("Main page")
	ctx.Response.Header.SetContentType("text/html")
	ctx.WriteString(`
<html>
<head>
	<title>OAuth-2 Test</title>
</head>
<body>

	<h2>OAuth-2 Test</h2>
	<p>
		Login with the following,
	</p>
	<ul>
	<form action="/login_gl">
    <input type="submit" value="Sign in with Google" />
</form>

	</ul>
</body>
</html>	
	
	`)
}

func (s *MyServer) LoginPage(ctx *fasthttp.RequestCtx) {
	log.Println("Login page handler")
	URL, err := url.Parse(s.oauthConf.Endpoint.AuthURL)
	if err != nil {
		log.Printf("Redirect URL parse error: %v", err)
	}
	parameters := url.Values{}
	parameters.Add("client_id", s.oauthConf.ClientID)
	parameters.Add("scope", strings.Join(s.oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", s.oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", s.oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()

	log.Printf("Redirect URL: %s", url)
	ctx.Redirect(url, fasthttp.StatusTemporaryRedirect)
}

func (s *MyServer) CallbackPage(ctx *fasthttp.RequestCtx) {
	log.Printf("Callback from google")

	state := ctx.FormValue("state")
	log.Printf("State string: %s", state)

	code := string(ctx.FormValue("code"))

	if code == "" {
		log.Println("Code not found")
		ctx.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := ctx.FormValue("error_reason")
		if string(reason) == "user_denied" {
			ctx.Write([]byte("User has denied Permission.."))
		}
		return
	}

	log.Printf("Code string: %s", code)
	token, err := s.oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Printf("Exchange error: %v", err)
		ctx.WriteString("Exchange error: " + err.Error())
		return
	}

	log.Printf("Access token: %s", token.AccessToken)
	log.Printf("Refresh token: %s", token.RefreshToken)
	log.Printf("Expiration time: %s", token.Expiry.String())
	log.Printf("Token type: %s", token.TokenType)

	_, respBody, err := fasthttp.Get(nil, "https://www.googleapis.com/oauth2/v2/userinfo?access_token="+url.QueryEscape(token.AccessToken))
	if err != nil {
		log.Printf("Getting userinfo by access token error: %s", err)
		ctx.WriteString("Getting userinfo by access token error: " + err.Error())
		return
	}

	log.Printf("User info: %s", respBody)

	ctx.Write([]byte("Hello, I'm protected\n"))
	ctx.Write([]byte(string(respBody)))
}

func main() {
	server := &MyServer{
		oauthConf: &oauth2.Config{
			ClientID:     "513855496494-71nmse5glb83okg5jdd1d51jao1ppmpj.apps.googleusercontent.com",
			ClientSecret: "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",
			RedirectURL:  "http://localhost:8080/google_redir",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		},
		oauthStateString: "SomeRandomString",
	}

	r := fasthttprouter.New()
	r.GET("/login_gl", server.LoginPage)
	r.GET("/google_redir", server.CallbackPage)
	r.GET("/", server.MainPage)

	fasthttp.ListenAndServe(":8080", r.Handler)
}
