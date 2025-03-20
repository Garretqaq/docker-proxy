package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
}

func newDockerProxy() *dockerProxy {
	return &dockerProxy{}
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
	upstreamHost, _ := routeByHosts(hostTop)

	// 处理token请求
	if strings.Contains(r.URL.Path, "/token") {
		dp.handleTokenRequest(w, r)
		return
	}

	// 处理网页请求
	if strings.Contains(userAgent, "mozilla") || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/search") || strings.HasPrefix(r.URL.Path, "/_") || strings.HasPrefix(r.URL.Path, "/api/") {
		// 代理到Docker Hub网页
		upstream, err := url.Parse("https://hub.docker.com")
		if err != nil {
			http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			// 添加必要的请求头
			req.Header.Set("Origin", "https://hub.docker.com")
			req.Header.Set("Referer", "https://hub.docker.com/")
			if req.Header.Get("Accept") == "" {
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			}
		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			// 添加必要的响应头
			resp.Header.Set("Access-Control-Allow-Origin", "*")
			resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			resp.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
			return nil
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Error during web proxy request: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		}

		proxy.ServeHTTP(w, r)
		return
	}

	// 处理v2 API请求
	if strings.HasPrefix(r.URL.Path, "/v2") {
		// 如果是registry API v2请求，直接转发到registry-1.docker.io
		upstream, err := url.Parse("https://" + upstreamHost)
		if err != nil {
			http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
			return
		}

		// 创建反向代理
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			// 处理library/前缀
			if upstreamHost == defaultHubHost {
				// 使用正则表达式匹配路径
				if strings.HasPrefix(req.URL.Path, "/v2/") && !strings.HasPrefix(req.URL.Path, "/v2/library/") {
					// 移除开头的/v2/
					path := strings.TrimPrefix(req.URL.Path, "/v2/")
					// 直接使用剩余的路径
					req.URL.Path = "/v2/" + path
				}
			}

			// 保留认证信息
			if auth := req.Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}

			log.Printf("Proxying request to: %s%s\n", req.Host, req.URL.Path)
		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			// 修改认证头
			if auth := resp.Header.Get("Www-Authenticate"); auth != "" {
				resp.Header.Set("Www-Authenticate",
					strings.ReplaceAll(auth, authURL, "https://"+r.Host))
			}

			// 添加CORS头
			resp.Header.Set("Access-Control-Allow-Origin", "*")
			resp.Header.Set("Access-Control-Expose-Headers", "*")
			resp.Header.Set("Cache-Control", "max-age=1500")

			return nil
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Error during proxy request: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		}

		proxy.ServeHTTP(w, r)
		return
	}

	// 其他请求使用默认的反向代理处理
	upstream, err := url.Parse("https://" + upstreamHost)
	if err != nil {
		http.Error(w, "Failed to parse upstream URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host

		// 保留原始请求头
		if auth := req.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// 修改认证头
		if auth := resp.Header.Get("Www-Authenticate"); auth != "" {
			resp.Header.Set("Www-Authenticate",
				strings.ReplaceAll(auth, authURL, "https://"+r.Host))
		}

		// 添加CORS头
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Expose-Headers", "*")
		resp.Header.Set("Cache-Control", "max-age=1500")

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
	if scope := q.Get("scope"); scope != "" {
		// 如果scope包含repository:，需要处理repository名称
		if strings.Contains(scope, "repository:") {
			parts := strings.Split(scope, ":")
			if len(parts) >= 2 {
				repoPath := strings.Split(parts[1], "/")
				// 如果不是library开头，直接使用完整路径
				if len(repoPath) > 0 && repoPath[0] != "library" {
					newScope := fmt.Sprintf("repository:%s:%s", strings.Join(repoPath, "/"), parts[len(parts)-1])
					q.Set("scope", newScope)
					r.URL.RawQuery = q.Encode()
				}
			}
		}
	}

	tokenURL := authURL + r.URL.Path + "?" + r.URL.RawQuery

	req, err := http.NewRequest(r.Method, tokenURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	req.Header = r.Header.Clone()
	req.Header.Set("Host", "auth.docker.io")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	io.Copy(w, resp.Body)
}

func main() {
	proxy := newDockerProxy()

	server := &http.Server{
		Addr:    ":9000",
		Handler: proxy,
	}

	log.Printf("Starting Docker registry proxy server on %s\n", server.Addr)
	log.Fatal(server.ListenAndServe())
}
