<div style="text-align: center">
  <p align="center">
      <i>自建Docker镜像加速服务</i>
  </p>
</div>

<div align="center">

[![GitHub contributors](https://img.shields.io/github/contributors/Garretqaq/docker-proxy)](https://github.com/Garretqaq/docker-proxy/graphs/contributors)
[![GitHub Issues](https://img.shields.io/github/issues/dqzboy/Docker-Proxy.svg)](https://github.com/dqzboy/Docker-Proxy/issues)
[![GitHub Pull Requests](https://img.shields.io/github/stars/dqzboy/Docker-Proxy)](https://github.com/dqzboy/Docker-Proxy)
[![HitCount](https://views.whatilearened.today/views/github/dqzboy/Docker-Proxy.svg)](https://github.com/dqzboy/Docker-Proxy)
[![GitHub license](https://img.shields.io/github/license/dqzboy/Docker-Proxy)](https://github.com/dqzboy/Docker-Proxy/blob/main/LICENSE)

---

## ✨ 开发原因

1、很多docker的镜像加速，都失效了拉取docker变的麻烦

2、使用部署[Cloudflare Workers](https://github.com/dqzboy/Workers-Proxy-Docker)搭建，容易受Cloudflare封禁止

3、一键部署，只需要便捷简单的加速docker，还能顺带访问一下docker hub网站。需要复杂且代理多个网站，可参考[Docker-Proxy](https://github.com/dqzboy/Docker-Proxy)

## 📝 准备工作

⚠️  **重要**：选择一台国外服务器，并且未被墙。对于域名，无需进行国内备案。你也可以通过一些平台申请免费域名。在部署过程中，如果选择安装Caddy，它将自动配置HTTPS，推荐使用。若选择部署Nginx服务，则需要自行申请一个免费的SSL证书，或者通过其他方式来实现SSL加密。

**方式一：** [Acme.sh自动生成和续订Lets Encrypt免费SSL证书](https://www.dqzboy.com/16437.html)

**方式二：** 域名托管到[Cloudflare 开启免费SSL证书](https://www.cloudflare.com/zh-cn/application-services/products/ssl/)

**方式三：** 可通过第三方平台，申请免费的域名证书(免费一般都为DV证书)，适用于个人网站、博客和小型项目

---

## 🔨 功能

- 一键部署Docker镜像代理服务的功能，支持基于官方Docker Registry的镜像代理. 
- 支持主流Linux发行版操作系统,例如Centos、Ubuntu、Rocky、Debian、Rhel、Windows等，支持主流ARCH架构下部署，包括linux/amd64、linux/arm64
- 支持代理访问hub.docker.com网站

## 📦 部署

### 通过二进制脚本部署

**1.** 下载对应平台的二进制文件

**2.** 运行服务 (Linux amd64为例)

```sh
./docker-proxy-1.0.0-linux-amd64
```

**3.** 访问<你的ip>:9000出现如下图，即解锁成功～

![截图](https://md-server.oss-cn-guangzhou.aliyuncs.com/images/1742438458226.png)

### Docker 部署

**1.** 执行 `docker`  命令启动容器服务

```sh
# 运行容器
docker run -d -p 9000:9000 --name docker-proxy songguangzhi/docker-proxy 

# 查看容器日志
docker logs -f [容器ID或名称]
```

**2.** 如果你对Nginx或Caddy不熟悉,那么你可以使用你熟悉的服务进行代理。也可以直接通过IP+端口的方式访问

**3.** 访问<你的ip>:9000出现如下图，即解锁成功～

![截图](https://md-server.oss-cn-guangzhou.aliyuncs.com/images/1742438458226.png)

## ✨ 使用 （caddy和nginx选一个，推荐caddy）

#### 配置caddy   [安装文档](https://caddy2.dengxiaolong.com/docs/install)

**1.** **修改Caddyfile,增加配置**

```sh

your_domain_name {
    reverse_proxy localhost:9000 {
        header_up Host {host}
        header_up X-Real-IP {remote_addr}
        header_up X-Forwarded-For {remote_addr}
        header_up X-Nginx-Proxy true
    }
}

```

**2.** **Caddy重载**

```
caddy reload
```

#### 配置nginx

**1.修改nginx配置文件，并修改配置里的域名和证书部分** <br>

```
## docker hub
server {
    listen       80;
    listen       443 ssl;
    ## 填写绑定证书的域名
    server_name  hub.your_domain_name;
    ## 证书文件名称（填写你证书存放的路径和名称）
    ssl_certificate your_domain_name.crt;
    ## 私钥文件名称（填写你证书存放的路径和名称）
    ssl_certificate_key your_domain_name.key;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    ssl_buffer_size 8k;

    proxy_connect_timeout 600;
    proxy_send_timeout    600;
    proxy_read_timeout    600;
    send_timeout          600;

    location / {
        proxy_pass   http://localhost:51000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;        
        proxy_set_header X-Nginx-Proxy true;
        proxy_buffering off;
        proxy_redirect off;
    }
}
```

**2.** **nginx重载配置**

```
sudo nginx -s reload
```

<br/>

#### 解析配置

**1.在你的DNS服务提供商将相应的访问域名解析到部署docker proxy服务的机器IP上** <br>
**2.修改Docker的daemon.json配置，配置你自建的Registry地址。修改后重启docker**

```powershell
~]# vim /etc/docker/daemon.json
{
    "registry-mirrors": [ "https://your_domain_name" ]
}
```

> **说明：** 配置了`daemon.json`之后，现在拉取镜像无需指定你的加速地址，直接执行`docker pull`拉取你需要的镜像即可。下面的步骤是你在没有配置`daemon.json`的时候，拉取镜像需要加上你的加速地址才可以正常拉取。

---

** 使用自建的 Registry 地址替换官方的 Registry 地址拉取镜像**

```powershell
# docker hub Registry
## 源：nginx:latest
## 替换
docker pull your_domain_name/library/nginx:latest

# Google Registry
## 源：gcr.io/google-containers/pause:3.1
## 替换：
docker pull your_domain_name/google-containers/pause:3.1
```

<br/>

## License

docker-proxy is available under the [Apache 2 license](./LICENSE)
