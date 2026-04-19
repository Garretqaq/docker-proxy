package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	defaultHubHost = "registry-1.docker.io"
	authURL        = "https://auth.docker.io"
)

var (
	blockedUserAgents = []string{"netcraft"}
)

// 路由配置
var routes = map[string]string{
	"quay":       "quay.io",
	"gcr":        "gcr.io",
	"k8s-gcr":    "k8s.gcr.io",
	"k8s":        "registry.k8s.io",
	"ghcr":       "ghcr.io",
	"cloudsmith": "docker.cloudsmith.io",
	"nvcr":       "nvcr.io",
	"test":       "registry-1.docker.io",
}

// 根据主机名前缀选择上游地址
func routeByHosts(host string) (string, bool) {
	if upstream, ok := routes[host]; ok {
		return upstream, false
	}
	return defaultHubHost, true
}

type dockerProxy struct {
	transport  *http.Transport
	httpClient *http.Client
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{ResponseWriter: w}
}

func (lw *loggingResponseWriter) WriteHeader(statusCode int) {
	if lw.statusCode == 0 {
		lw.statusCode = statusCode
	}
	lw.ResponseWriter.WriteHeader(statusCode)
}

func (lw *loggingResponseWriter) Write(p []byte) (int, error) {
	if lw.statusCode == 0 {
		lw.statusCode = http.StatusOK
	}
	n, err := lw.ResponseWriter.Write(p)
	lw.bytes += int64(n)
	return n, err
}

func (lw *loggingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if lw.statusCode == 0 {
		lw.statusCode = http.StatusOK
	}
	if rf, ok := lw.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		lw.bytes += n
		return n, err
	}
	n, err := io.Copy(lw.ResponseWriter, r)
	lw.bytes += n
	return n, err
}

func (lw *loggingResponseWriter) Flush() {
	if flusher, ok := lw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (lw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := lw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (lw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lw.ResponseWriter
}

func registryRequestType(path string) string {
	switch {
	case strings.Contains(path, "/blobs/"):
		return "blob"
	case strings.Contains(path, "/manifests/"):
		return "manifest"
	case path == "/v2/" || path == "/v2":
		return "ping"
	default:
		return "other"
	}
}

func (dp *dockerProxy) logRegistryRequest(r *http.Request, upstreamHost string, statusCode int, bytes int64, start time.Time) {
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}
	mb := float64(bytes) / (1024 * 1024)
	speed := mb / elapsed.Seconds()
	log.Printf(
		"registry_request method=%s host=%s upstream=%s path=%s type=%s status=%d bytes=%d duration_ms=%d speed_mb_s=%.2f range=%q",
		r.Method,
		r.Host,
		upstreamHost,
		r.URL.Path,
		registryRequestType(r.URL.Path),
		statusCode,
		bytes,
		elapsed.Milliseconds(),
		speed,
		r.Header.Get("Range"),
	)
}

func newDockerProxy() *dockerProxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		DisableCompression:    true,
		ReadBufferSize:        128 * 1024,
		WriteBufferSize:       128 * 1024,
	}

	return &dockerProxy{
		transport: transport,
		httpClient: &http.Client{
			Timeout:   45 * time.Second,
			Transport: transport,
		},
	}
}

func (dp *dockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userAgent := strings.ToLower(r.UserAgent())
	for _, blocked := range blockedUserAgents {
		if strings.Contains(userAgent, blocked) {
			dp.serveNginxPage(w)
			return
		}
	}

	hostname := r.Host
	hostTop := strings.Split(hostname, ".")[0]

	upstreamHost, isDefaultHub := routeByHosts(hostTop)

	if strings.HasPrefix(r.URL.Path, "/v1/search") {
		dp.handleSearchRequest(w, r)
		return
	}

	if strings.Contains(r.URL.Path, "/token") {
		dp.handleTokenRequest(w, r)
		return
	}

	if strings.Contains(userAgent, "mozilla") || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/search") || strings.HasPrefix(r.URL.Path, "/_") || strings.HasPrefix(r.URL.Path, "/api/") {
		dp.handleWebRequest(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/v2") {
		dp.handleRegistryRequest(w, r, upstreamHost, isDefaultHub)
		return
	}

	dp.handleDefaultRequest(w, r, upstreamHost)
}

func (dp *dockerProxy) handleRegistryRequest(w http.ResponseWriter, r *http.Request, upstreamHost string, isDefaultHub bool) {
	_ = isDefaultHub
	start := time.Now()

	upstream, err := url.Parse("https://" + upstreamHost)
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	incomingHost := r.Host
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host

		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", incomingHost)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Expose-Headers", "*")

		if auth := resp.Header.Get("Www-Authenticate"); auth != "" {
			resp.Header.Set("Www-Authenticate", strings.ReplaceAll(auth, authURL, "https://"+incomingHost))
		}

		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		if req.Context().Err() != nil {
			return
		}
		log.Printf("registry proxy error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
	}

	logWriter := newLoggingResponseWriter(w)
	proxy.ServeHTTP(logWriter, r)

	statusCode := logWriter.statusCode
	if statusCode == 0 {
		if r.Context().Err() != nil {
			statusCode = 499
		} else {
			statusCode = http.StatusOK
		}
	}
	dp.logRegistryRequest(r, upstreamHost, statusCode, logWriter.bytes, start)
}

func (dp *dockerProxy) handleWebRequest(w http.ResponseWriter, r *http.Request) {
	upstream, err := url.Parse("https://hub.docker.com")
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host

		if cookies := r.Cookies(); len(cookies) > 0 {
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
		}

		req.Header.Set("Origin", "https://hub.docker.com")
		req.Header.Set("Referer", "https://hub.docker.com/")
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		resp.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
		resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (dp *dockerProxy) handleDefaultRequest(w http.ResponseWriter, r *http.Request, upstreamHost string) {
	upstream, err := url.Parse("https://" + upstreamHost)
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Expose-Headers", "*")
		return nil
	}

	proxy.ServeHTTP(w, r)
}

// 服务Nginx页面
func (dp *dockerProxy) serveNginxPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`)
}

// 处理token请求
func (dp *dockerProxy) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	scope := q.Get("scope")
	service := q.Get("service")

	if scope != "" && strings.Contains(scope, "repository:") {
		parts := strings.Split(scope, ":")
		if len(parts) >= 2 {
			repoPath := strings.Split(parts[1], "/")
			if len(repoPath) == 1 {
				newScope := fmt.Sprintf("repository:library/%s:%s", repoPath[0], parts[len(parts)-1])
				q.Set("scope", newScope)
			}
		}
	}

	if service == "" {
		q.Set("service", "registry.docker.io")
	}

	tokenURL := authURL + "/token?" + q.Encode()
	log.Printf("Token request URL: %s", tokenURL)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, tokenURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	req.Header.Set("User-Agent", r.UserAgent())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Host", "auth.docker.io")

	resp, err := dp.httpClient.Do(req)
	if err != nil {
		log.Printf("Get token failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	w.WriteHeader(resp.StatusCode)

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Copy token response body failed: %v", err)
	}
	log.Printf("token_request status=%d bytes=%d duration_ms=%d scope=%q", resp.StatusCode, n, time.Since(start).Milliseconds(), q.Get("scope"))
}

// 处理搜索请求
func (dp *dockerProxy) handleSearchRequest(w http.ResponseWriter, r *http.Request) {
	upstream, err := url.Parse("https://index.docker.io")
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
		req.URL.RawQuery = r.URL.RawQuery

		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", r.UserAgent())

		if auth := r.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		resp.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		resp.Header.Set("Content-Type", "application/json")
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func main() {
	proxy := newDockerProxy()

	server := &http.Server{
		Addr:              ":9000",
		Handler:           proxy,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("Starting Docker registry proxy server on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
