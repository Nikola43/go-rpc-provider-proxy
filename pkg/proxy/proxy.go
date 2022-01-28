package proxy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nikola43/go-rpc-provider-proxy/pkg/cache"
	"github.com/nikola43/go-rpc-provider-proxy/pkg/slack"
	"go.uber.org/ratelimit"
)

// Config ...
type Config struct {
	ProxyURL                   string
	ProxyMethod                string
	Port                       string
	LogLevel                   string
	AuthorizationSecret        string
	BlockedIps                 []string
	AlwaysAllowedIps           []string
	LeakyBucketLimitPerSecond  int
	SoftCapIPRequestsPerMinute int
	HardCapIPRequestsPerMinute int
	SlackWebhookURL            string
	SlackChannel               string
}

// Proxy ...
type Proxy struct {
	HttpClient                 *http.Client
	ProxyURL                   *url.URL
	ProxyMethod                string
	Port                       string
	maxIdleConnections         int
	requestTimeout             int
	method                     string
	SessionID                  int
	LogLevel                   string
	AuthorizationSecret        string
	Ratelimit                  ratelimit.Limiter
	BlockedIps                 map[string]bool
	AlwaysAllowedIps           map[string]bool
	Cache                      *cache.Cache
	leakyBucketLimitPerSecond  int
	SoftCapIPRequestsPerMinute int
	HardCapIPRequestsPerMinute int
	slackWebhookURL            string
	slackChannel               string
}

// NewProxy ...
func NewProxy(config *Config) *Proxy {
	if config == nil {
		panic("Proxy config is required")
	}

	port := "8000"
	if config.Port != "" {
		port = config.Port
	}

	method := "GET"
	if config.ProxyMethod != "" {
		method = strings.ToUpper(config.ProxyMethod)
	}

	lps := 100
	if config.LeakyBucketLimitPerSecond != 0 {
		lps = config.LeakyBucketLimitPerSecond
	}
	rl := ratelimit.New(lps)
	cache := cache.NewCache()

	blockedIps := make(map[string]bool, len(config.BlockedIps))
	alwaysAllowedIps := make(map[string]bool, len(config.AlwaysAllowedIps))

	for _, ip := range config.BlockedIps {
		blockedIps[ip] = true
	}

	for _, ip := range config.AlwaysAllowedIps {
		alwaysAllowedIps[ip] = true
	}

	softCapIPRequestsPerMinute := 100
	if config.SoftCapIPRequestsPerMinute != 0 {
		softCapIPRequestsPerMinute = config.SoftCapIPRequestsPerMinute
	}

	hardCapIPRequestsPerMinute := 1000
	if config.HardCapIPRequestsPerMinute != 0 {
		hardCapIPRequestsPerMinute = config.HardCapIPRequestsPerMinute
	}

	proxyURL, err := url.Parse(config.ProxyURL)
	if err != nil {
		panic(err)
	}

	return &Proxy{
		Port:                       port,
		ProxyURL:                   proxyURL,
		ProxyMethod:                method,
		maxIdleConnections:         100,
		requestTimeout:             3600,
		SessionID:                  0,
		LogLevel:                   config.LogLevel,
		AuthorizationSecret:        config.AuthorizationSecret,
		Ratelimit:                  rl,
		BlockedIps:                 blockedIps,
		AlwaysAllowedIps:           alwaysAllowedIps,
		Cache:                      cache,
		leakyBucketLimitPerSecond:  lps,
		SoftCapIPRequestsPerMinute: softCapIPRequestsPerMinute,
		HardCapIPRequestsPerMinute: hardCapIPRequestsPerMinute,
		slackWebhookURL:            config.SlackWebhookURL,
		slackChannel:               config.SlackChannel,
	}
}

// PingHandler ...
func (p *Proxy) PingHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "pong")
}

// HealthCheckHandler ...
func (p *Proxy) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	payload := []byte(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":42}`)
	url := fmt.Sprintf("http://127.0.0.1:%v", p.Port)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		err := fmt.Sprintf("Health check error: %s", err.Error())
		http.Error(w, err, http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		err := fmt.Sprintf("Health check error: %s", err.Error())
		http.Error(w, err, http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err := fmt.Sprintf("Health check error: got status code %v", resp.StatusCode)
		http.Error(w, err, resp.StatusCode)
		return
	}

	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

// ProxyHandler ...
func (p *Proxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	p.Ratelimit.Take()
	p.SessionID++
	sessionID := p.SessionID

	r.Close = true
	defer r.Body.Close()

	origin := r.Header.Get("Origin")
	ipAddress, err := GetIP(r)
	if err != nil {
		fmt.Printf("ERROR ID=%v: %s\n", sessionID, err)
		http.Error(w, "", http.StatusBadRequest)
	}

	if _, ok := p.BlockedIps[ipAddress]; ok {
		err := errors.New("Blocked: Ip address blocked")
		fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
		http.Error(w, "", http.StatusTooManyRequests)
		return
	}

	rateLimitCacheKey := fmt.Sprintf("Ratelimit:%s", ipAddress)

	// don't rate limit IPs that are always allowed
	if _, ok := p.AlwaysAllowedIps[ipAddress]; !ok {
		count := 0
		cached, expiration, found := p.Cache.Get(rateLimitCacheKey)
		if found {
			count = cached.(int)
		}

		tryAgainInSeconds := expiration.Sub(time.Now()).Seconds()

		// send slack notification on soft cap rate limit reached for IP
		if count == p.SoftCapIPRequestsPerMinute {
			notification := fmt.Sprintf("⚠️ SOFT cap reached (%v req/min) IP=%s ORIGIN=%s PROXY=%s ID=%v\n", count, ipAddress, origin, p.ProxyURL.Hostname(), sessionID)
			fmt.Printf(notification)
			p.SendNotification(notification)
		}

		// send slack notification on hard cap rate limit reached for IP
		if count == p.HardCapIPRequestsPerMinute {
			seenCacheKey := fmt.Sprintf("seen:%s", ipAddress)
			if _, _, found := p.Cache.Get(seenCacheKey); !found {
				notification := fmt.Sprintf("🚫 HARD cap reached (%v req/min) IP=%s ORIGIN=%s PROXY=%s ID=%v\n", count, ipAddress, origin, p.ProxyURL.Hostname(), sessionID)
				fmt.Printf(notification)
				p.SendNotification(notification)

				// makes sure that notification is only sent once during rate limit cycle
				p.Cache.Set(seenCacheKey, true, time.Duration(expiration.Unix()-time.Now().Unix())*time.Second)
			}
		}

		// prevent request if hard cap rate limit reached for IP
		if count >= p.HardCapIPRequestsPerMinute {
			err := fmt.Sprintf("Too many requests: Rate limit exceeded. Try again in %.0fs", tryAgainInSeconds)
			fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
			http.Error(w, "", http.StatusTooManyRequests)
			return
		}

		count++
		p.Cache.Set(rateLimitCacheKey, count, 1*time.Minute)
	}

	// check base64 encoded bearer token if auth check enabled
	if p.AuthorizationSecret != "" {
		reqToken := r.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer")
		if (len(splitToken)) != 2 {
			err := errors.New("Unauthorized: Auth token is required")
			fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		reqToken = strings.TrimSpace(splitToken[1])
		decoded, err := base64.StdEncoding.DecodeString(reqToken)
		if err != nil {
			fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		decodedToken := string(decoded)
		if p.AuthorizationSecret != decodedToken {
			err := errors.New("Unauthorized: Invalid auth token")
			fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
	}

	bodyBuf, _ := ioutil.ReadAll(r.Body)

	// make copies
	bodyRdr1 := ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	bodyRdr2 := ioutil.NopCloser(bytes.NewBuffer(bodyBuf))

	requestBody, err := ioutil.ReadAll(bodyRdr1)
	if err != nil {
		fmt.Printf("ERROR ID=%v: %s %s\n", sessionID, err, ipAddress)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if p.LogLevel == "debug" {
		fmt.Printf("REQUEST ID=%v: %s [%s] %s %s %s %s\n", sessionID, ipAddress, time.Now().String(), r.Method, r.URL.String(), r.UserAgent(), string(requestBody))
	}

	if r.Method == "OPTIONS" {
		w.Header().Del("Access-Control-Allow-Credentials")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Accept,Origin,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE,PATCH")
		w.Header().Set("Access-Control-Max-Age", "1728000")
		w.Header().Set("Content-Type", "text/plain charset=UTF-8")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(204)
		return
	}

	if r.Method != p.ProxyMethod {
		http.Error(w, "Not supported", http.StatusNotFound)
		return
	}

	req, err := http.NewRequest(p.ProxyMethod, p.ProxyURL.String(), bodyRdr2)
	if err != nil {
		fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Close request after sending request and reading response
	req.Close = true
	defer req.Body.Close()

	// copy headers to request
	for k, v := range r.Header {
		req.Header.Set(k, v[0])
	}

	// Connection header informs server that client wants to close connection after response.
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Del("Host")

	// setting the content length disables chunked transfer encoding,
	// which is required to make proxy work with Alchemy
	req.ContentLength = int64(len(requestBody))

	if p.LogLevel == "debug" {
		httpMsg, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		fmt.Println(string(httpMsg))
	}

	resp, err := p.HttpClient.Do(req)
	if err != nil {
		fmt.Printf("ERROR ID=%v: %s %s\n", sessionID, err, ipAddress)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// re-use connection
	defer resp.Body.Close()

	// response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ERROR ID=%v: %s IP=%s\n", sessionID, err, ipAddress)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}

	w.Header().Del("Access-Control-Allow-Credentials")
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Accept,Origin,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE,PATCH")

	if p.LogLevel == "debug" {
		fmt.Printf("RESPONSE ID=%v: %s [%s] %v %s %s %s\n", sessionID, ipAddress, time.Now().String(), resp.StatusCode, r.Method, r.URL, body)
	}

	w.WriteHeader(200)
	w.Write(body)
}

func (p *Proxy) SetHttpClient(client *http.Client) {
	p.HttpClient = client
}


func (p *Proxy) createHTTPClient() (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: p.maxIdleConnections,
		DisableKeepAlives:   true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(p.requestTimeout) * time.Second,
	}

	return client, nil
}

// sendNotification ...
func (p *Proxy) SendNotification(msg string) {
	if p.slackWebhookURL == "" {
		return
	}

	err := slack.SendNotification(&slack.SendNotificationInput{
		WebhookURL: p.slackWebhookURL,
		Message:    msg,
		Channel:    p.slackChannel,
		Username:   "proxy",
		IconEmoji:  "computer",
	})
	if err != nil {
		fmt.Printf("SLACK ERROR %v\n", err)
	}
}
