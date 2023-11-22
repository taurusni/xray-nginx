## XRay 基于 前置Nginx 的 vless+ws+tls 一键安装脚本

### 安装
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/taurusni/xray-nginx/main/install.sh" && chmod +x install.sh && bash install.sh
```

**注意**: 
1. 脚本默认使用443端口和80端口。可自行修改
2. 脚本默认只支持ubuntu 20+。可自行修改
3. 非匹配请求转发到提供的反代网站
4. 脚本只支持IPv4
5. 客户端配置可以参考[模板](https://github.com/lxhao61/integrated-examples)

### 证书

脚本支持自动生成 let's encrypted 证书且自动续期

### 启动方式

```
启动 Xray:
systemctl start xray

停止 Xray:
systemctl stop xray

启动 Nginx:
systemctl start nginx

停止 Nginx:
systemctl stop nginx
```

### 相关目录

```
Nginx 目录
/etc/nginx
-- /etc/nginx/nginx.conf
-- /etc/nginx/conf.d/${domain}.conf

Xray 配置目录:
/usr/local/etc/xray
-- /usr/local/etc/xray/config.json

证书目录: 
/usr/local/etc/xray/cert
-- /usr/local/etc/xray/cert/${domain}.cert
-- /usr/local/etc/xray/cert/${domain}.key
```

### 链接
- [ProjectX](https://xtls.github.io/)
- [Reality](https://github.com/XTLS/REALITY)
- [Xray-install](https://github.com/XTLS/Xray-install)
- [Tutorial](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)
- [Server Test](https://www.ssllabs.com/projects/index.html)
- [客户端v2rayN 6.17+](https://itlanyan.com/v2ray-clients-download/)