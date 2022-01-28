package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	"github.com/nikola43/go-rpc-provider-proxy/pkg/proxy"
	"github.com/panjf2000/ants"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var rpcProxies []*proxy.Proxy

var RPCClients = make(map[string]int, 0)

func main() {

	defer ants.Release()
	//var wg sync.WaitGroup

	// system config
	numCpu := runtime.NumCPU()
	usedCpu := numCpu
	runtime.GOMAXPROCS(usedCpu)
	fmt.Println("")
	fmt.Println(color.YellowString("  ----------------- System Info -----------------"))
	fmt.Println(color.CyanString("\t    Number CPU cores available: "), color.GreenString(strconv.Itoa(numCpu)))
	fmt.Println(color.MagentaString("\t    Used of CPU cores: "), color.YellowString(strconv.Itoa(usedCpu)))
	fmt.Println(color.MagentaString(""))

	port := "9000"
	host := fmt.Sprintf("0.0.0.0:%v", port)

	rpcProxies = make([]*proxy.Proxy, 0)

	client := &http.Client{
		Transport: &http.Transport{MaxIdleConnsPerHost: 5, DisableKeepAlives: true},
		Timeout:   time.Duration(3600) * time.Second,
	}

	rpcProxy1 := proxy.NewProxy(&proxy.Config{
		ProxyURL:         "https://avax-node-1.projectx.financial",
		ProxyMethod:      "POST",
		Port:             port,
		BlockedIps:       []string{"123.123.123.123"},
		AlwaysAllowedIps: []string{"127.0.0.1"},
	})
	rpcProxy1.SetHttpClient(client)
	rpcProxies = append(rpcProxies, rpcProxy1)

	rpcProxy2 := proxy.NewProxy(&proxy.Config{
		ProxyURL:         "https://avax-node-3.projectx.financial",
		ProxyMethod:      "POST",
		Port:             port,
		BlockedIps:       []string{"123.123.123.123"},
		AlwaysAllowedIps: []string{"127.0.0.1"},
	})
	rpcProxy2.SetHttpClient(client)
	rpcProxies = append(rpcProxies, rpcProxy2)

	rpcProxy3 := proxy.NewProxy(&proxy.Config{
		ProxyURL:         "https://avax-node-4.projectx.financial",
		ProxyMethod:      "POST",
		Port:             port,
		BlockedIps:       []string{"123.123.123.123"},
		AlwaysAllowedIps: []string{"127.0.0.1"},
	})
	rpcProxy3.SetHttpClient(client)
	rpcProxies = append(rpcProxies, rpcProxy3)


	rpcProxy4 := proxy.NewProxy(&proxy.Config{
		ProxyURL:         "https://avax-node-5.projectx.financial",
		ProxyMethod:      "POST",
		Port:             port,
		BlockedIps:       []string{"123.123.123.123"},
		AlwaysAllowedIps: []string{"127.0.0.1"},
	})
	rpcProxy4.SetHttpClient(client)
	rpcProxies = append(rpcProxies, rpcProxy4)


	r := mux.NewRouter()

	r.HandleFunc("/node/{hash_id}", nodeProxy)


	//http.HandleFunc("/ping", ss)
	//http.HandleFunc("/health", ss)
	//http.HandleFunc("/node/{a}/aaa", nodeProxy)

	//fmt.Printf("Proxying %s %s\n", rpcProxy.ProxyMethod, rpcProxy.ProxyURL.String())
	http.ListenAndServe(host, r)
}

func nodeProxy(w http.ResponseWriter, r *http.Request) {

	hashId := mux.Vars(r)["hash_id"]
	unescapedPath, err := url.PathUnescape(hashId)
	if err != nil {
		fmt.Println(unescapedPath)
	}
	fmt.Println(hashId)


	rand.Seed(time.Now().UnixNano())
	min := 0
	max := len(rpcProxies) - 1
	ran := rand.Intn(max-min+1) + min

	//get id from params

	// call nodes api

	// if okay continue, else send unauthorized

	p := rpcProxies[ran]

	fmt.Println("node")
	fmt.Println(p.ProxyURL)

	p.Ratelimit.Take()
	p.SessionID++
	sessionID := p.SessionID

	r.Close = true
	defer r.Body.Close()

	origin := r.Header.Get("Origin")
	ipAddress, err := proxy.GetIP(r)

	fmt.Println("ipAddress")
	fmt.Println(ipAddress)
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

	rateLimitCacheKey := fmt.Sprintf("ratelimit:%s", ipAddress)

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


func handHealth(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "pong")
}

func handProxy(w http.ResponseWriter, r *http.Request) {

}