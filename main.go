package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	AllowedDomains     []*regexp.Regexp
	GitHubClientID     string
	GitHubClientSecret string
	GitHubHostname     string

	GitLabClientID     string
	GitLabClientSecret string
	GitLabHostname     string
}

var cookieValueRegex = regexp.MustCompile(`([a-z-]+?)_([0-9a-f]{32})`)

var outputTemplate = template.Must(template.New("output").Parse(`
<!doctype html>
<html>
<body>
<script>
(() => {
  window.addEventListener('message', ({ data, origin }) => {
	if (data === 'authorizing:{{.provider}}') {
	  window.opener?.postMessage(
		'authorization:{{ .provider }}:{{ .state }}:'+ JSON.stringify({{ .content }}),
		origin
	  );
	}
  });
  window.opener?.postMessage('authorizing:{{ .provider }}', '*');
})();
</script></body></html>
`))

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	mux := http.NewServeMux()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	domainRegexes, err := generateAllowedDomainRegexes(os.Getenv("ALLOWED_DOMAINS"))
	if err != nil {
		return err
	}

	config := Config{
		AllowedDomains:     domainRegexes,
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubHostname:     os.Getenv("GITHUB_HOSTNAME"),
		GitLabClientID:     os.Getenv("GITLAB_CLIENT_ID"),
		GitLabClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
		GitLabHostname:     os.Getenv("GITLAB_HOSTNAME"),
	}

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	mux.Handle("GET /auth", handleAuth(&config, log))
	mux.Handle("GET /callback", handleCallback(&config, &client, log))

	srv := http.Server{
		ReadTimeout: 1 * time.Second,
		Handler:     mux,
		Addr:        ":1314",
	}

	lis, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}

	eg := errgroup.Group{}

	eg.Go(func() error {
		log.Info("listening", slog.String("addr", ":1314"))
		err = srv.Serve(lis)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		return nil
	})

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	shudownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.InfoContext(shudownCtx, "shutting down", slog.String("timeout", (10*time.Second).String()))

	err = srv.Shutdown(shudownCtx)
	if err != nil {
		return err
	}

	return eg.Wait()
}

func handleAuth(config *Config, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		domain := r.URL.Query().Get("site_id")

		allowed := false
		for _, allowedDomain := range config.AllowedDomains {
			if allowedDomain.MatchString(domain) {
				allowed = true
			}
		}
		if !allowed {
			outputHTML(log, w, provider, "", "Your domain is not allowed to use the authenticator.", "UNSUPPORTED_DOMAIN")
			return
		}

		csrfToken := strings.ReplaceAll(uuid.New().String(), "-", "")
		authURL := ""

		switch provider {
		case "github":
			if config.GitHubClientID == "" || config.GitHubClientSecret == "" {
				outputHTML(log, w, provider, "", "OAuth app client ID or secret is not configured.", "MISCONFIGURED_CLIENT")
				return
			}

			queryValues := url.Values{}
			queryValues.Add("client_id", config.GitHubClientID)
			queryValues.Add("scope", "repo,user")
			queryValues.Add("state", csrfToken)

			authURL = fmt.Sprintf("https://%s/login/oauth/authorize?%s", config.GitHubHostname, queryValues.Encode())
		case "gitlab":
			if config.GitLabClientID == "" || config.GitLabClientSecret == "" {
				outputHTML(log, w, provider, "", "OAuth app client ID or secret is not configured.", "MISCONFIGURED_CLIENT")
				return
			}

			queryValues := url.Values{}
			queryValues.Add("client_id", config.GitLabClientID)
			queryValues.Add("redirect_uri", fmt.Sprintf("%s://%s/callback", r.URL.Scheme, r.URL.Host))
			queryValues.Add("response_type", "code")
			queryValues.Add("scope", "api")
			queryValues.Add("state", csrfToken)

			authURL = fmt.Sprintf("https://%s/oauth/authorize?%s", config.GitLabHostname, queryValues.Encode())
		default:
			outputHTML(log, w, "", "", "Your Git backend is not supported by the authenticator.", "UNSUPPORTED_BACKEND")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "csrf-token",
			HttpOnly: true,
			Path:     "/",
			MaxAge:   600,
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			Value:    fmt.Sprintf("%s_%s", provider, csrfToken),
		})
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func handleCallback(config *Config, client *http.Client, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("csrf-token")
		if errors.Is(err, http.ErrNoCookie) {
			log.WarnContext(r.Context(), "missing cookie")
			outputHTML(log, w, "", "", "Potential CSRF attack detected. Authentication flow aborted.", "CSRF_DETECTED")
			return
		}
		if err != nil {
			log.WarnContext(r.Context(), "error getting cookie", slog.String("error", err.Error()))
			http.Error(w, "Something went wrong processing the request.", http.StatusInternalServerError)
			return
		}

		matches := cookieValueRegex.FindStringSubmatch(cookie.Value)
		if len(matches) != 3 {
			log.WarnContext(r.Context(), "cookie value does not match regex", slog.String("cookie", cookie.Value))
			outputHTML(log, w, "", "", "Potential CSRF attack detected. Authentication flow aborted.", "CSRF_DETECTED")
			return
		}

		provider := matches[1]
		csrfToken := matches[2]
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			log.WarnContext(r.Context(), "no auth code or state in query params", slog.Bool("code", code != ""), slog.Bool("state", state != ""))
			outputHTML(log, w, provider, "", "Failed to receive an authorization code. Please try again later.", "AUTH_CODE_REQUEST_FAILED")
			return
		}

		if csrfToken == "" || state != csrfToken {
			log.WarnContext(r.Context(), "empty CSRF token in cookie or mismatch", slog.Bool("token_empty", csrfToken == ""), slog.Bool("token_mismatch", state != csrfToken))
			outputHTML(log, w, provider, "", "Potential CSRF attack detected. Authentication flow aborted.", "CSRF_DETECTED")
			return
		}

		tokenURL := ""
		var requestBody map[string]string

		switch provider {
		case "github":
			if config.GitHubClientID == "" || config.GitHubClientSecret == "" {
				outputHTML(log, w, provider, "", "OAuth app client ID or secret is not configured.", "MISCONFIGURED_CLIENT")
				return
			}

			tokenURL = fmt.Sprintf("https://%s/login/oauth/access_token", config.GitHubHostname)
			requestBody = map[string]string{
				"code":          code,
				"client_id":     config.GitHubClientID,
				"client_secret": config.GitHubClientSecret,
			}
		case "gitlab":
			if config.GitLabClientID == "" || config.GitLabClientSecret == "" {
				outputHTML(log, w, provider, "", "OAuth app client ID or secret is not configured.", "MISCONFIGURED_CLIENT")
				return
			}

			tokenURL = fmt.Sprintf("https://%s/oauth/token", config.GitLabHostname)
			requestBody = map[string]string{
				"code":          code,
				"client_id":     config.GitLabClientID,
				"client_secret": config.GitLabClientSecret,
				"grant_type":    "authorization_code",
				"redirect_uri":  fmt.Sprintf("%s://%s/callback", r.URL.Scheme, r.URL.Host),
			}
		default:
			outputHTML(log, w, "", "", "Your Git backend is not supported by the authenticator.", "UNSUPPORTED_BACKEND")
			return
		}

		requestBodyJSON, err := json.Marshal(requestBody)
		if err != nil {
			log.ErrorContext(r.Context(), "error marshalling token request JSON", slog.String("error", err.Error()))
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, bytes.NewReader(requestBodyJSON))
		if err != nil {
			log.ErrorContext(r.Context(), "error creating token request", slog.String("error", err.Error()))
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.ErrorContext(r.Context(), "token request failure", slog.String("error", err.Error()))
			outputHTML(log, w, provider, "", "Failed to request an access token. Please try again later.", "TOKEN_REQUEST_FAILED")
			return
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.ErrorContext(r.Context(), "error reading token response", slog.String("error", err.Error()))
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		var responseBody map[string]string

		err = json.Unmarshal(respBody, &responseBody)
		if err != nil {
			log.ErrorContext(r.Context(), "token endpoint not parseable", slog.String("data", string(respBody)), slog.String("error", err.Error()))
			outputHTML(log, w, provider, "", "Server responded with malformed data. Please try again later.", "MALFORMED_RESPONSE")
			return
		}

		outputHTML(log, w, provider, responseBody["access_token"], "", "")
	})
}

func generateAllowedDomainRegexes(allowedDomains string) ([]*regexp.Regexp, error) {
	domains := strings.Split(allowedDomains, ",")

	regexes := make([]*regexp.Regexp, 0, len(allowedDomains))

	for _, d := range domains {
		domainRegex, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(d), `\*`, `.+`) + "$")
		if err != nil {
			return nil, err
		}

		regexes = append(regexes, domainRegex)
	}

	return regexes, nil
}

func outputHTML(log *slog.Logger, w http.ResponseWriter, provider, token, errorText, errorCode string) {
	state := "success"
	if errorText != "" {
		state = "error"
	}

	var content map[string]string

	switch state {
	case "success":
		content = map[string]string{
			"provider": provider,
			"token":    token,
		}
	case "error":
		content = map[string]string{
			"provider":  provider,
			"error":     errorText,
			"errorCode": errorCode,
		}
	}

	var templateContext = map[string]any{
		"state":    state,
		"provider": provider,
		"content":  content,
	}

	err := outputTemplate.ExecuteTemplate(w, "output", templateContext)
	if err != nil {
		log.Error("error rendering output", slog.String("error", err.Error()))
		http.Error(w, "could not render output", http.StatusInternalServerError)
	}
}
