package postreceive

import (
	"io/ioutil"
	"fmt"
	"net/http"
	"encoding/json"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/hmac"
	"encoding/hex"
	"hash"
	"strings"
	"crypto/subtle"
	"github.com/homedepot/github-webhook/events"
	"github.com/homedepot/github-webhook/executor"
	"expvar"
)

//https://developer.github.com/webhooks/

const POST = "POST"
const APPLICATION_JSON = "application/json"
const USER_AGENT = "User-Agent"
const X_GITHUB_DELIVERY = "X-Github-Delivery"
const X_GITHUB_EVENT = "X-GitHub-Event"
const X_HUB_SIGNATURE = "X-Hub-Signature"
const X_HUB_SIGNATURE_256 = "X-Hub-Signature-256"

func HttpHandler(w http.ResponseWriter, req *http.Request) {

	metrics.Add("requests", 1)

	if req.Body == nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	defer req.Body.Close()

	if !strings.EqualFold(APPLICATION_JSON, req.Header.Get("Content-Type")) {
		http.Error(w, "Invalid content type", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	if !strings.EqualFold(POST,req.Method) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		metrics.Add("error", 1)
		return
	}

	if userAgent := req.Header.Get(USER_AGENT); !strings.HasPrefix(userAgent,"GitHub") {
		http.Error(w, "Invalid User Agent Header", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	delivery := req.Header.Get(X_GITHUB_DELIVERY)
	if len(delivery) == 0 {
		http.Error(w, "Missing X-Github-Delivery Header", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	eventType := req.Header.Get(X_GITHUB_EVENT)
	if len(eventType) == 0 {
		http.Error(w, "Missing X-GitHub-Event Header", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	eventTypeId, found := events.EventTypes[eventType]
	if !found {
		http.Error(w, "Unsupported Github-Event Type", http.StatusBadRequest)
		metrics.Add("error", 1)
		return
	}

	metrics.Add(eventType, 1)

	if eventTypeId == events.PING {
		w.WriteHeader(http.StatusOK)
		return
	}

	payload, readError := ioutil.ReadAll(req.Body)
	if readError != nil {
		http.Error(w, fmt.Sprint(readError), http.StatusInternalServerError)
		metrics.Add("error", 1)
		return
	}

	if !validateSignature(payload, secret, req) {
		http.Error(w, "Signature was not valid", http.StatusUnauthorized)
		metrics.Add("error", 1)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		http.Error(w, fmt.Sprint(readError), http.StatusInternalServerError)
		metrics.Add("error", 1)
		return
	}

	event := events.Event{
		ID: delivery,
		Type: eventTypeId,
		Name: eventType,
		Data: data,
	}

	err := executor.ProcessEvent(event)
	if err != nil {
		http.Error(w, fmt.Sprint(readError), http.StatusInternalServerError)
		metrics.Add("error", 1)
		return
	}

	w.WriteHeader(http.StatusOK)

}

var secret string

func SetSecret(value string) {
	secret = value
}

// validateSignature verifies the GitHub HMAC signature of the payload. It fails
// closed: an empty secret or a missing/invalid signature rejects the request.
// X-Hub-Signature-256 (HMAC-SHA256) is preferred; the legacy X-Hub-Signature
// (HMAC-SHA1) header is only consulted when the SHA-256 header is absent.
func validateSignature(payload []byte, secret string, req *http.Request) bool {

	if len(secret) == 0 {
		return false
	}

	if sig := req.Header.Get(X_HUB_SIGNATURE_256); len(sig) > 0 {
		return verifyHmac(sha256.New, "sha256=", sig, payload, secret)
	}

	if sig := req.Header.Get(X_HUB_SIGNATURE); len(sig) > 0 {
		return verifyHmac(sha1.New, "sha1=", sig, payload, secret)
	}

	return false
}

func verifyHmac(h func() hash.Hash, prefix string, signature string, payload []byte, secret string) bool {
	if !strings.HasPrefix(signature, prefix) {
		return false
	}
	given, err := hex.DecodeString(signature[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(h, []byte(secret))
	mac.Write(payload)
	return subtle.ConstantTimeCompare(given, mac.Sum(nil)) == 1
}

var metrics *expvar.Map

func SetMetrics(m *expvar.Map) {
	metrics = m
}

