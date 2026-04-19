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
	"sync"
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

// 1MB 缓冲池，用于 blob 流式传输和 ReverseProxy 内部拷贝
var blobCopyPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 1<<20)
		return &buf
	},
}

// 实现 httputil.BufferPool 接口，给 ReverseProxy 使用
type proxyBufPool struct{}

func (proxyBufPool) Get() []byte  { return *blobCopyPool.Get().(*[]byte) }
func (proxyBufPool) Put(b []byte) { blobCopyPool.Put(&b) }

// hop-by-hop headers，转发请求时跳过
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func copyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
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
	httpClient *http.Client // token 等小请求，带超时
	blobClient *http.Client // blob 下载，无超时，自动跟随 CDN 重定向
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
		// 禁用 HTTP/2：其每流 64KB 初始窗口在高延迟链路上严重限制大文件吞吐
		// Go 1.24+ 规则：有自定义 DialContext 且 ForceAttemptHTTP2=false 时自动禁用 HTTP/2
		ForceAttemptHTTP2: false,
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		DisableCompression:    true,
		ReadBufferSize:        256 * 1024,
		WriteBufferSize:       256 * 1024,
	}

	return &dockerProxy{
		transport: transport,
		httpClient: &http.Client{
			Timeout:   45 * time.Second,
			Transport: transport,
		},
		blobClient: &http.Client{
			Transport: transport,
			// 无全局超时：blob 下载时间不可预测
			// 默认 CheckRedirect 最多跟随 10 次重定向（跟随 CDN 307）
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 {
					log.Printf("blob_redirect from=%s to=%s", via[len(via)-1].URL.Host, req.URL.Host)
				}
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
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

	// blob GET/HEAD 单独处理：使用 blobClient 跟随 CDN 重定向 + 1MB 缓冲流式传输
	if strings.Contains(r.URL.Path, "/blobs/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		dp.handleBlobRequest(w, r, upstreamHost)
		return
	}

	start := time.Now()

	upstream, err := url.Parse("https://" + upstreamHost)
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	incomingHost := r.Host
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport
	proxy.BufferPool = proxyBufPool{}
	proxy.FlushInterval = -1 // 立即刷新，减少数据积压

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

// handleBlobRequest 直接用 blobClient 下载 blob，自动跟随 CDN 307 重定向，避免客户端绕过代理
func (dp *dockerProxy) handleBlobRequest(w http.ResponseWriter, r *http.Request, upstreamHost string) {
	start := time.Now()

	targetURL := "https://" + upstreamHost + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	copyRequestHeaders(req.Header, r.Header)

	resp, err := dp.blobClient.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		log.Printf("blob request error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h := w.Header()
	for k, vs := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "*")

	lw := newLoggingResponseWriter(w)
	lw.WriteHeader(resp.StatusCode)

	if r.Method != http.MethodHead {
		buf := blobCopyPool.Get().(*[]byte)
		defer blobCopyPool.Put(buf)
		if _, err = io.CopyBuffer(lw, resp.Body, *buf); err != nil && r.Context().Err() == nil {
			log.Printf("blob copy error: %v", err)
		}
	}

	dp.logRegistryRequest(r, upstreamHost, lw.statusCode, lw.bytes, start)
}

func (dp *dockerProxy) handleWebRequest(w http.ResponseWriter, r *http.Request) {
	upstream, err := url.Parse("https://hub.docker.com")
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.transport
	proxy.BufferPool = proxyBufPool{}
	proxy.FlushInterval = -1

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
	proxy.BufferPool = proxyBufPool{}
	proxy.FlushInterval = -1

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
	proxy.BufferPool = proxyBufPool{}
	proxy.FlushInterval = -1

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
