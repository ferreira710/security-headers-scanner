// The Netlify entry point. It is an adapter and nothing else: it turns the
// Lambda event into an *http.Request, hands it to the same api.Handler the
// container runs, and turns the recorded response back into a Lambda result.
//
// Netlify routes /api/* here through the redirect in netlify.toml, so the
// handler keeps seeing the same paths it sees in dev and in Compose.
package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/ferreira710/security-headers-scanner/backend/internal/api"
	"github.com/ferreira710/security-headers-scanner/backend/internal/config"
)

// functionPrefix is where Netlify mounts this function. Requests arrive either
// as the original /api/... path or rewritten to this prefix, depending on how
// they were routed, so the adapter normalises both back to /api/...
const functionPrefix = "/.netlify/functions/scan"

// Built once: the Lambda container is reused across invocations, so the rate
// limiter and the concurrency cap survive between requests on a warm instance.
var handler = buildHandler()

// netlifyFunctionBudget is how long Netlify lets a synchronous function run.
// Our own ceiling has to land *under* it, or a slow target gets us killed
// mid-flight and the caller sees Netlify's error page instead of our typed
// timeout.
const netlifyFunctionBudget = 8 * time.Second

func buildHandler() http.Handler {
	settings := config.FromEnv()
	if settings.TotalTimeout > netlifyFunctionBudget {
		settings.TotalTimeout = netlifyFunctionBudget
	}
	// Here we are always behind Netlify's edge, and it sets the client IP
	// header itself rather than passing a client-supplied one through. That is
	// the condition the rate limiter needs before it trusts a forwarded IP.
	settings.TrustProxyHeaders = true
	return api.NewServer(settings).Handler()
}

// normalizePath maps whatever Netlify hands us onto the routes the mux knows.
func normalizePath(path string) string {
	if strings.HasPrefix(path, "/api/") {
		return path
	}
	if rest, found := strings.CutPrefix(path, functionPrefix); found {
		rest = strings.TrimPrefix(rest, "/")
		// A bare hit on the function, with no sub-path, means /api/scan: that
		// is the only thing worth POSTing here.
		if rest == "" || rest == "scan" {
			return "/api/scan"
		}
		return "/api/" + rest
	}
	return path
}

func decodeBody(request events.APIGatewayProxyRequest) []byte {
	if !request.IsBase64Encoded {
		return []byte(request.Body)
	}
	decoded, err := base64.StdEncoding.DecodeString(request.Body)
	if err != nil {
		return nil
	}
	return decoded
}

func handle(request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	target := normalizePath(request.Path)
	if request.QueryStringParameters != nil {
		values := make([]string, 0, len(request.QueryStringParameters))
		for key, value := range request.QueryStringParameters {
			values = append(values, key+"="+value)
		}
		if len(values) > 0 {
			target += "?" + strings.Join(values, "&")
		}
	}

	req := httptest.NewRequest(request.HTTPMethod, target, bytes.NewReader(decodeBody(request)))
	for name, value := range request.Headers {
		req.Header.Set(name, value)
	}
	for name, values := range request.MultiValueHeaders {
		req.Header.Del(name)
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	// Give the rate limiter something real to key on even if the Netlify
	// header is missing; httptest's placeholder RemoteAddr would lump every
	// caller together.
	if ip := request.RequestContext.Identity.SourceIP; ip != "" {
		req.RemoteAddr = ip + ":0"
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	headers := map[string]string{}
	multiValue := map[string][]string{}
	for name, values := range result.Header {
		headers[name] = values[len(values)-1]
		if len(values) > 1 {
			multiValue[name] = values
		}
	}

	return &events.APIGatewayProxyResponse{
		StatusCode:        result.StatusCode,
		Headers:           headers,
		MultiValueHeaders: multiValue,
		Body:              recorder.Body.String(),
	}, nil
}

func main() {
	lambda.Start(handle)
}
