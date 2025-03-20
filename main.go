package main

import (
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

// 根据主机名选择对应的上游地址
func routeByHosts(host string) (string, bool) {
	if upstream, ok := routes[host]; ok {
		return upstream, false
	}
	return defaultHubHost, true
}

type dockerProxy struct {
	reverseProxy *httputil.ReverseProxy
	client       *http.Client
}

func newDockerProxy() *dockerProxy {
	return &dockerProxy{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSHandshakeTimeout: 10 * time.Second,
				IdleConnTimeout:     30 * time.Second,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
			},
		},
	}
}

func (dp *dockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 检查UA是否被屏蔽
	userAgent := strings.ToLower(r.UserAgent())
	for _, blocked := range blockedUserAgents {
		if strings.Contains(userAgent, blocked) {
			dp.serveNginxPage(w)
			return
		}
	}

	// 解析请求URL
	hostname := r.Host
	hostTop := strings.Split(hostname, ".")[0]

	// 获取上游地址
	upstreamHost, isDefaultHub := routeByHosts(hostTop)

	// 处理token请求
	if strings.Contains(r.URL.Path, "/token") {
		dp.handleTokenRequest(w, r)
		return
	}

	// 处理网页请求
	if strings.Contains(userAgent, "mozilla") || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/search") || strings.HasPrefix(r.URL.Path, "/_") || strings.HasPrefix(r.URL.Path, "/api/") {
		dp.handleWebRequest(w, r)
		return
	}

	// 处理镜像拉取请求
	if strings.HasPrefix(r.URL.Path, "/v2") {
		dp.handleRegistryRequest(w, r, upstreamHost, isDefaultHub)
		return
	}

	// 其他请求
	dp.handleDefaultRequest(w, r, upstreamHost)
}

func (dp *dockerProxy) handleRegistryRequest(w http.ResponseWriter, r *http.Request, upstreamHost string, isDefaultHub bool) {
	upstream, err := url.Parse("https://" + upstreamHost)
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	// 使用自定义传输处理大文件传输
	if r.Method == "GET" && (strings.Contains(r.URL.Path, "/blobs/") || strings.Contains(r.URL.Path, "/manifests/")) {
		dp.handleBlobRequest(w, r, upstreamHost)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host

		// 保持原始请求头
		if req.Header.Get("Range") != "" {
			log.Printf("处理范围请求: %s", req.Header.Get("Range"))
		}

		if isDefaultHub {
			path := req.URL.Path
			if strings.HasPrefix(path, "/v2/") && !strings.HasPrefix(path, "/v2/library/") {
				parts := strings.Split(path[4:], "/")
				if len(parts) > 0 && !strings.Contains(parts[0], "/") {
					req.URL.Path = "/v2/library/" + strings.Join(parts, "/")
				}
			}
		}
		log.Printf("代理请求到: %s%s", req.Host, req.URL.Path)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// 保持原始响应头
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Expose-Headers", "*")

		// 处理认证头
		if auth := resp.Header.Get("Www-Authenticate"); auth != "" {
			resp.Header.Set("Www-Authenticate",
				strings.ReplaceAll(auth, authURL, "https://"+r.Host))
		}

		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("代理请求错误: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// 处理大文件传输的方法
func (dp *dockerProxy) handleBlobRequest(w http.ResponseWriter, r *http.Request, upstreamHost string) {
	upstreamURL := fmt.Sprintf("https://%s%s", upstreamHost, r.URL.Path)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	// 创建上游请求
	upstreamReq, err := http.NewRequest(r.Method, upstreamURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制原始请求头
	upstreamReq.Header = r.Header.Clone()
	upstreamReq.Header.Set("Host", upstreamHost)

	// 发送请求
	resp, err := dp.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)

	// 使用大缓冲区进行流式传输
	buf := make([]byte, 32*1024) // 32KB 缓冲区
	if _, err := io.CopyBuffer(w, resp.Body, buf); err != nil {
		log.Printf("传输数据时发生错误: %v", err)
		return
	}
}

func (dp *dockerProxy) handleWebRequest(w http.ResponseWriter, r *http.Request) {
	upstream, err := url.Parse("https://hub.docker.com")
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = dp.client.Transport

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host

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
	proxy.Transport = dp.client.Transport

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
	// 修改scope参数中的repository名称
	q := r.URL.Query()
	scope := q.Get("scope")
	service := q.Get("service")

	if scope != "" {
		// 如果scope包含repository:，需要处理repository名称
		if strings.Contains(scope, "repository:") {
			parts := strings.Split(scope, ":")
			if len(parts) >= 2 {
				repoPath := strings.Split(parts[1], "/")
				// 如果不是library开头且只有一个部分，添加library前缀
				if len(repoPath) == 1 {
					newScope := fmt.Sprintf("repository:library/%s:%s", repoPath[0], parts[len(parts)-1])
					q.Set("scope", newScope)
					r.URL.RawQuery = q.Encode()
				}
			}
		}
	}

	tokenURL := authURL + "/token"
	if service == "" {
		q.Set("service", "registry.docker.io")
	}

	tokenURL = tokenURL + "?" + q.Encode()
	log.Printf("Token请求URL: %s", tokenURL)

	req, err := http.NewRequest(r.Method, tokenURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制认证头
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// 设置基本请求头
	req.Header.Set("User-Agent", r.UserAgent())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Host", "auth.docker.io")

	// 发送请求
	resp, err := dp.client.Do(req)
	if err != nil {
		log.Printf("获取token失败: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("复制响应体失败: %v", err)
	}
}

func main() {
	proxy := newDockerProxy()

	server := &http.Server{
		Addr:    ":9000",
		Handler: proxy,
		// 增加服务器超时设置/songguangzhi/yolo/blobs/sha256:7cf63256a31a4cc44f6defe8e1af95363aee5fa75f30a248d95cae684f87c53c
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("Starting Docker registry proxy server on %s\n", server.Addr)
	log.Fatal(server.ListenAndServe())
}
