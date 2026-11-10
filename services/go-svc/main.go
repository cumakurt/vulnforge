// VulnForge Lab — go-svc
//
// Intentionally vulnerable Go service used for scanner benchmarking.
// Covers SSRF, race conditions, path traversal, command injection and related
// classes. WARNING: never expose this service outside an isolated lab.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var (
	labControlURL = envOr("LAB_CONTROL_URL", "http://lab-control:9100")
	oobURL        = envOr("OOB_COLLECTOR_URL", "http://oob-collector:9000")
	listenAddr    = ":" + envOr("PORT", "8090")
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func labTrigger(vulnID string, r *http.Request, extra map[string]any) {
	body := map[string]any{
		"kind":       "vuln_triggered",
		"vuln_id":    vulnID,
		"service":    "go-svc",
		"request_id": r.Header.Get("X-Request-Id"),
		"ts":         time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
	}
	for key, value := range extra {
		body[key] = value
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return
	}

	// Fire-and-forget so lab telemetry never slows the target response.
	go func() {
		client := &http.Client{Timeout: time.Second}
		resp, err := client.Post(labControlURL+"/__lab/events", "application/json", bytes.NewReader(payload))
		if err == nil {
			resp.Body.Close()
		}
	}()
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// ─── SSRF ────────────────────────────────────────────────────────────────────

// @vuln id=GO-001 name="SSRF in image proxy" cwe=CWE-918 owasp=A10:2021 type=ssrf level=1 param=url method=GET service=go-svc url=/go/proxy param_loc=query needs_oob=false auth=false detection=active tags=ssrf proof_kind=marker proof_desc="Internal metadata credentials are returned through the proxy"
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	// !! INTENTIONALLY VULNERABLE — no scheme or host filtering !!
	resp, err := http.Get(target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	labTrigger("GO-001", r, map[string]any{"url": target, "status": resp.StatusCode})
	writeJSON(w, http.StatusOK, map[string]any{"status": resp.StatusCode, "body": string(body)})
}

// @control id=GO-001-C twin_of=GO-001 url=/go/proxy_safe method=GET param=url service=go-svc param_loc=query
func proxySafeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid url"})
		return
	}
	if isPrivateHost(parsed.Hostname()) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "destination not allowed"})
		return
	}

	resp, err := (&http.Client{Timeout: 4 * time.Second}).Get(target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream unavailable"})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{"status": resp.StatusCode})
}

func isPrivateHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	// Single-label hostnames resolve to internal Docker services.
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return true
	}
	prefixes := []string{"127.", "10.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18."}
	for _, prefix := range prefixes {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}
	return false
}

// ─── Blind SSRF ──────────────────────────────────────────────────────────────

// @vuln id=GO-002 name="Blind SSRF via webhook ping" cwe=CWE-918 owasp=A10:2021 type=ssrf-blind level=2 param=url method=GET service=go-svc url=/go/pingback param_loc=query needs_oob=true auth=false detection=active tags=ssrf,blind,oob proof_kind=oob proof_desc="The server issues a request to the supplied URL; only an out-of-band callback proves it"
func pingbackHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	// !! INTENTIONALLY VULNERABLE — no validation, response discarded !!
	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		if resp, err := client.Get(target); err == nil {
			resp.Body.Close()
		}
	}()

	labTrigger("GO-002", r, map[string]any{"url": target})
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

// @control id=GO-002-C twin_of=GO-002 url=/go/pingback_safe method=GET param=url service=go-svc param_loc=query
func pingbackSafeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || isPrivateHost(parsed.Hostname()) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "destination not allowed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

// ─── Race condition ──────────────────────────────────────────────────────────

type coupon struct {
	mu           sync.Mutex
	used         bool
	redemptions  int
	balanceCents int64
}

var demoCoupon = &coupon{balanceCents: 10000}

// @vuln id=GO-003 name="Race condition allows a coupon to be redeemed repeatedly" cwe=CWE-362 owasp=A04:2021 type=race-condition level=3 param=code method=POST service=go-svc url=/go/coupon/redeem param_loc=body needs_oob=false auth=false detection=logic tags=logic,race,toctou proof_kind=marker proof_desc="Parallel redemptions credit the balance more than once"
func couponRedeemHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	if payload.Code != "WELCOME10" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid coupon"})
		return
	}

	// !! INTENTIONALLY VULNERABLE — check and update are not atomic !!
	if demoCoupon.used {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "coupon already used"})
		return
	}

	// Simulated work between the check and the write widens the race window.
	time.Sleep(120 * time.Millisecond)

	demoCoupon.used = true
	demoCoupon.balanceCents += 1000
	demoCoupon.redemptions++

	labTrigger("GO-003", r, map[string]any{"redemptions": demoCoupon.redemptions})
	writeJSON(w, http.StatusOK, map[string]any{
		"redeemed":    true,
		"balance":     demoCoupon.balanceCents,
		"redemptions": demoCoupon.redemptions,
	})
}

// @control id=GO-003-C twin_of=GO-003 url=/go/coupon/redeem_safe method=POST param=code service=go-svc param_loc=body
func couponRedeemSafeHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	demoCoupon.mu.Lock()
	defer demoCoupon.mu.Unlock()

	if payload.Code != "WELCOME10" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid coupon"})
		return
	}
	if demoCoupon.used {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "coupon already used"})
		return
	}
	demoCoupon.used = true
	demoCoupon.balanceCents += 1000
	writeJSON(w, http.StatusOK, map[string]any{"redeemed": true, "balance": demoCoupon.balanceCents})
}

// Status endpoints used by the smoke test to observe the race outcome.
func couponStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"used":        demoCoupon.used,
		"redemptions": demoCoupon.redemptions,
		"balance":     demoCoupon.balanceCents,
	})
}

func couponStatusSafeHandler(w http.ResponseWriter, r *http.Request) {
	demoCoupon.mu.Lock()
	defer demoCoupon.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"used":        demoCoupon.used,
		"redemptions": demoCoupon.redemptions,
		"balance":     demoCoupon.balanceCents,
	})
}

// ─── Path traversal ──────────────────────────────────────────────────────────

// @vuln id=GO-005 name="Path traversal in static file resolver" cwe=CWE-22 owasp=A01:2021 type=path-traversal level=1 param=file method=GET service=go-svc url=/go/file param_loc=query needs_oob=false auth=false detection=active tags=file,traversal proof_kind=marker proof_desc="Files outside the documents directory can be read"
func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")

	// !! INTENTIONALLY VULNERABLE — path joined without cleaning/allowlist !!
	path := filepath.Join("/app/documents", name)
	content, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "file not found"})
		return
	}

	if strings.Contains(name, "..") {
		labTrigger("GO-005", r, map[string]any{"payload": name})
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(content)
}

// @control id=GO-005-C twin_of=GO-005 url=/go/file_safe method=GET param=file service=go-svc param_loc=query
func fileSafeHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	allowed := map[string]bool{"readme.txt": true, "about.txt": true}
	if !allowed[name] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid file"})
		return
	}
	content, err := os.ReadFile(filepath.Join("/app/documents", name))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "file not found"})
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(content)
}

// ─── Command injection ───────────────────────────────────────────────────────

// @vuln id=GO-006 name="Command injection in diagnostic runner" cwe=CWE-78 owasp=A03:2021 type=os-command level=1 param=cmd method=GET service=go-svc url=/go/diag param_loc=query needs_oob=false auth=false detection=active tags=injection,command,rce proof_kind=marker proof_desc="Shell metacharacters execute and their output is returned"
func diagHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")

	// !! INTENTIONALLY VULNERABLE — sh -c with concatenated input !!
	out, err := exec.Command("sh", "-c", "echo "+command).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "output": string(out)})
		return
	}

	if strings.ContainsAny(command, ";|&`$()") {
		labTrigger("GO-006", r, map[string]any{"payload": command})
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": string(out)})
}

// @control id=GO-006-C twin_of=GO-006 url=/go/diag_safe method=GET param=cmd service=go-svc param_loc=query
func diagSafeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	for _, char := range command {
		if !(char == ' ' || char == '-' || char == '.' || char == '_' ||
			(char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid characters"})
			return
		}
	}
	// SAFE: no shell involved.
	out, _ := exec.Command("echo", command).CombinedOutput()
	writeJSON(w, http.StatusOK, map[string]any{"output": string(out)})
}

// ─── Open redirect ───────────────────────────────────────────────────────────

// @vuln id=GO-007 name="Open redirect in continue parameter" cwe=CWE-601 owasp=A01:2021 type=open-redirect level=1 param=next method=GET service=go-svc url=/go/continue param_loc=query needs_oob=false auth=false detection=active tags=redirect proof_kind=marker proof_desc="Location header points at an arbitrary external host"
func continueHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") || strings.HasPrefix(next, "//") {
		labTrigger("GO-007", r, map[string]any{"payload": next})
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// @control id=GO-007-C twin_of=GO-007 url=/go/continue_safe method=GET param=next service=go-svc param_loc=query
func continueSafeHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	switch next {
	case "/", "/go/file_safe", "/go/diag_safe":
		http.Redirect(w, r, next, http.StatusFound)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid redirect target"})
	}
}

// ─── OTP brute force ────────────────────────────────────────────────────────

type otpState struct {
	mu       sync.Mutex
	failures int
}

var demoOTP = &otpState{}

// @vuln id=GO-008 name="OTP verification without attempt limit" cwe=CWE-307 owasp=A04:2021 type=otp-bruteforce level=2 param=code method=POST service=go-svc url=/go/otp/verify param_loc=json needs_oob=false auth=false detection=logic tags=auth,otp,rate-limit proof_kind=marker proof_desc="Unlimited wrong codes are accepted and the correct OTP still validates afterwards"
func otpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	// !! INTENTIONALLY VULNERABLE — no attempt counter, no lockout !!
	if payload.Code != "4821" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"verified": false})
		return
	}
	labTrigger("GO-008", r, map[string]any{"attempts": demoOTP.failures + 1})
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// @control id=GO-008-C twin_of=GO-008 url=/go/otp/verify_safe method=POST param=code service=go-svc param_loc=json
func otpVerifySafeHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	demoOTP.mu.Lock()
	defer demoOTP.mu.Unlock()

	if demoOTP.failures >= 5 {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts"})
		return
	}
	if payload.Code != "4821" {
		demoOTP.failures++
		writeJSON(w, http.StatusUnauthorized, map[string]any{"verified": false})
		return
	}
	demoOTP.failures = 0
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// ─── Business logic ─────────────────────────────────────────────────────────

// @vuln id=GO-009 name="Negative purchase amount credits the wallet" cwe=CWE-840 owasp=A04:2021 type=negative-amount level=1 param=amount method=POST service=go-svc url=/go/wallet/purchase param_loc=json needs_oob=false auth=false detection=logic tags=logic,business-logic,integer proof_kind=marker proof_desc="A negative amount increases the balance instead of being rejected"
func purchaseHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Amount int64 `json:"amount"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	// !! INTENTIONALLY VULNERABLE — no sign or range validation !!
	demoCoupon.balanceCents -= payload.Amount

	if payload.Amount < 0 {
		labTrigger("GO-009", r, map[string]any{"amount": payload.Amount})
	}
	writeJSON(w, http.StatusOK, map[string]any{"balance": demoCoupon.balanceCents})
}

// @control id=GO-009-C twin_of=GO-009 url=/go/wallet/purchase_safe method=POST param=amount service=go-svc param_loc=json
func purchaseSafeHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Amount int64 `json:"amount"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	if payload.Amount <= 0 || payload.Amount > 50000 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "amount out of range"})
		return
	}
	demoCoupon.mu.Lock()
	demoCoupon.balanceCents -= payload.Amount
	balance := demoCoupon.balanceCents
	demoCoupon.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"balance": balance})
}

// ─── Verbose errors ─────────────────────────────────────────────────────────

// @vuln id=GO-010 name="Panic handler returns full Go stack trace" cwe=CWE-209 owasp=A05:2021 type=verbose-error level=1 param=input method=GET service=go-svc url=/go/error param_loc=query needs_oob=false auth=false detection=config tags=misconfiguration,info-leak proof_kind=marker proof_desc="Response contains goroutine dump and source file paths"
func errorHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	if input == "" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	}

	// !! INTENTIONALLY VULNERABLE — internal stack trace sent to the client !!
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "panic: failed to process %q\ngoroutine 1 [running]:\n%s", input, debug.Stack())
	labTrigger("GO-010", r, map[string]any{"input": input})
}

// @control id=GO-010-C twin_of=GO-010 url=/go/error_safe method=GET param=input service=go-svc param_loc=query
func errorSafeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("input") != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "request could not be processed", "correlation_id": "5f2c1a"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// @vuln id=GO-011 name="Permissive CORS policy with wildcard origin" cwe=CWE-942 owasp=A05:2021 type=cors-wildcard level=1 param=Origin method=GET service=go-svc url=/go/cors param_loc=header needs_oob=false auth=false detection=config tags=cors,misconfiguration proof_kind=marker proof_desc="Access-Control-Allow-Origin is * and credentials are allowed"
func corsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	labTrigger("GO-011", r, map[string]any{"origin": r.Header.Get("Origin")})
}

// @control id=GO-011-C twin_of=GO-011 url=/go/cors_safe method=GET param=Origin service=go-svc param_loc=header
func corsSafeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8000")
	w.Header().Set("Vary", "Origin")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── Lab endpoints ──────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "go-svc"})
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	demoCoupon.mu.Lock()
	demoCoupon.used = false
	demoCoupon.redemptions = 0
	demoCoupon.balanceCents = 10000
	demoCoupon.mu.Unlock()

	demoOTP.mu.Lock()
	demoOTP.failures = 0
	demoOTP.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/__lab/internal/reset", resetHandler)
	mux.HandleFunc("/__lab/internal/seed", resetHandler)

	mux.HandleFunc("/go/proxy", proxyHandler)
	mux.HandleFunc("/go/proxy_safe", proxySafeHandler)
	mux.HandleFunc("/go/pingback", pingbackHandler)
	mux.HandleFunc("/go/pingback_safe", pingbackSafeHandler)
	mux.HandleFunc("/go/coupon/redeem", couponRedeemHandler)
	mux.HandleFunc("/go/coupon/redeem_safe", couponRedeemSafeHandler)
	mux.HandleFunc("/go/coupon/status", couponStatusHandler)
	mux.HandleFunc("/go/coupon/status_safe", couponStatusSafeHandler)
	mux.HandleFunc("/go/file", fileHandler)
	mux.HandleFunc("/go/file_safe", fileSafeHandler)
	mux.HandleFunc("/go/diag", diagHandler)
	mux.HandleFunc("/go/diag_safe", diagSafeHandler)
	mux.HandleFunc("/go/continue", continueHandler)
	mux.HandleFunc("/go/continue_safe", continueSafeHandler)
	mux.HandleFunc("/go/otp/verify", otpVerifyHandler)
	mux.HandleFunc("/go/otp/verify_safe", otpVerifySafeHandler)
	mux.HandleFunc("/go/wallet/purchase", purchaseHandler)
	mux.HandleFunc("/go/wallet/purchase_safe", purchaseSafeHandler)
	mux.HandleFunc("/go/error", errorHandler)
	mux.HandleFunc("/go/error_safe", errorSafeHandler)
	mux.HandleFunc("/go/cors", corsHandler)
	mux.HandleFunc("/go/cors_safe", corsSafeHandler)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("[go-svc] listening on %s\n", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "[go-svc] server error: %v\n", err)
		os.Exit(1)
	}
}
