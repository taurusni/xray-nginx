#!/bin/bash

function PrintMessage(){
    echo -e "${1}\n"
}

function Judge(){
    if [[ 0 -eq $? ]]; then
        PrintOk "$1"
    else
        PrintErrorWithBackground "$1"
  fi
}

function PrintInformation(){
    PrintWithGreenPrefix "[INFO]" "${1}"
}

function PrintOk(){
    PrintWithGreenPrefix "[OK]" "${1}"
}

function PrintErrorWithBackground(){
    redFont="\033[31m[ERROR]\033[0m"
    redBackground="\033[41;37m${1}\033[0m"
    PrintMessage "${redFont} ${redBackground}"
    exit 1;
}

function PrintWithGreenPrefix(){
    prefix="\033[32m${1}\033[0m"
    blueFont="\033[36m${2}\033[0m"
    PrintMessage "${prefix} ${blueFont}"
}

function CheckRoot() {
    if [ 0 == "${UID}" ]; then
        PrintOk "当前用户是root用户，进入安装流程"
    else
        PrintErrorWithBackground "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    fi
}

function CheckSystem(){
    systemFile="/etc/os-release"
    if [[ -e "${systemFile}" ]];then
        id="$(grep "^ID=" "${systemFile}" | awk -F= '{print $2}')"
        version="$(grep "^VERSION_ID=" "${systemFile}" | awk -F= '{print $2}')"
        version="${version//\"/}"
        version="${version//\'/}"
        majorVersion="$(echo "${version}" | awk -F. '{print $1}')"
        if [[ "${id}" == "ubuntu" && "${majorVersion}" -ge 20 ]]; then
            PrintInformation "当前系统为${id}-${version}"
        else
            PrintErrorWithBackground "请使用Ubutntu 20.04以及以上!"
        fi
    else
        PrintErrorWithBackground "系统文件${systemFile}不存在!"
    fi
}

function EnablePortInFirewall(){
    if [[ $(which ufw) ]]; then
        ufw allow 443
        Judge "允许443端口"
        ufw allow 80
        Judge "允许80端口"
    fi
}

function UpgradePacakges(){
    apt update -y
    apt upgrade -y
}

function CheckPort() {
  if [[ 0 -eq $(lsof -i:"${1}" | grep -i -c "listen") ]]; then
    PrintOk "${1} 端口未被占用"
  else
    PrintInformation "检测到 $1 端口被占用，以下为 $1 端口占用信息"
    lsof -i:"$1"
    PrintInformation "5s 后将尝试自动 kill 占用进程"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    Judge "kill 完成"
    sleep 1
  fi
}

function CheckDomain() {
    read -rp "请输入你的域名信息:" domain
    domainIP=$(curl -sm8 https://ipget.net/?ip="${domain}")
    localIPVersion4=$(curl -s4m8 https://ipinfo.io | grep -Po 'ip[^0-9]*"\K[^"]*')
    if [[ "${domainIP}" == "${localIPVersion4}" ]]; then
        echo "${domain}"
    else
        echo "请确保域名正确并添加了正确的 A 记录，否则将无法正常使用!"
        echo 1
    fi
}

function CheckProxySite(){
    read -rp "请输入反向代理网站的域名:" site
    if [[ $(curl -sm8 https://ipget.net/?ip="${site}" | grep -i error -c) -eq 0 ]]; then
        echo "${site}"
    else
        echo "无法找到${site}"
        echo 1
    fi
}

function DoBasicOptimization() {
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf
}

function InstallXray() {
    if [[ -z "$(which xray)" ]]; then
        PrintInformation "安装 Xray"
    else
        PrintInformation "更新Xray"
    fi
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    Judge "Xray 安装"
    systemctl stop xray
    Judge "停止Xray"
}

function InstallNginx(){
    if [[ -z "$(which nginx)" ]]; then
        PrintInformation "安装 Nginx"
        apt install nginx -y
        Judge "Nginx 安装"
    else
        PrintOk "Nginx 已经安装"
    fi
    systemctl stop nginx
    Judge "停止Nginx"
}

function GenerateAPort(){
    while :
    do
        randomPort=$((RANDOM % (65535-10000+1) + 10000))
        if ! lsof -i :"${randomPort}" > /dev/null 2>&1; then
            echo "${randomPort}"
            break
        fi
    done
}

function GenerateAPath(){
    randomNum=$((RANDOM % 12 + 4))
    echo "/$(head -n 10 /dev/urandom | md5sum | head -c ${randomNum})/"
}

function GenerateCertificate(){
    PrintInformation "生成证书中..."
    domain="$1"
    xrayCertificateFolder="$2"
    xrayCertificate="$3"
    xrayCertificateKey="$4"
    mkdir -p "${xrayCertificateFolder}"
    apt install socat netcat -y
    Judge "安装 SSL 证书生成脚本依赖"
    curl https://get.acme.sh | sh
    Judge "安装 SSL 证书生成脚本"
    ln -s  /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    acme.sh --set-default-ca --server letsencrypt
    if acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        PrintOk "SSL 证书测试签发成功，开始正式签发"
        sleep 2
    else
        rm -rf "${HOME}/.acme.sh/${domain}_ecc"
        PrintErrorWithBackground "SSL 证书测试签发失败"
    fi

    if acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        PrintOk "SSL 证书生成成功"
        sleep 2
        mkdir -p "${xrayCertificateFolder}"
        if acme.sh --installcert -d "${domain}" --fullchainpath "${xrayCertificate}" --keypath "${xrayCertificateKey}" --ecc --force --reloadcmd "systemctl restart xray" --reloadcmd "systemctl restart nginx"; then
            PrintOk "证书配置成功"
            sleep 2
        fi
    else
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        PrintErrorWithBackground "SSL 证书生成失败"
    fi
}

function ConfigureDefaultNginx(){
    defaultConfigurationFile="/etc/nginx/nginx.conf"
    mkdir -p "/var/log/nginx/success"
    mkdir -p "/var/log/nginx/fail"
    chmod 777 "/var/log/nginx/success"
    chmod 777 "/var/log/nginx/fail"
    firstLine=$(head -n 1 "${defaultConfigurationFile}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    cat > "/etc/nginx/nginx.conf" <<EOF
    ${firstLine}
    worker_processes auto;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;
    worker_rlimit_nofile 65535;

    events {
        worker_connections  8192;
        use epoll;
        multi_accept on; 
    }

    http {
        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 30;
        types_hash_max_size 2048;
        reset_timedout_connection on;

        map \$time_iso8601 \$logdate{
            '~^(?<ymd>\d{4}-\d{2}-\d{2})' \$ymd;
            default 'date-not-found';
        }
        map \$status \$success {
            ~^[23]  1;
            default 0;
        }
        map \$status \$fail {
            ~^[23]  0;
            default 1;
        }
        log_format custom '\$remote_addr - \$remote_user [\$time_local] '
                        '\$ssl_protocol \$ssl_cipher '
                        '"\$request" \$status \$body_bytes_sent '
                        '"\$http_referer" "\$http_user_agent" '
                        '"\$http_x_forwarded_for" \$request_id '
                        'rt=\$request_time uct="\$upstream_connect_time" uht="\$upstream_header_time" urt="\$upstream_response_time"';
        access_log /var/log/nginx/success/\$logdate.log  custom if=\$success;
        access_log /var/log/nginx/fail/\$logdate.log  custom if=\$fail;
        error_log /var/log/nginx/error.log warn;

        gzip  on;
        gzip_disable "msie6";
        gzip_proxied any;
        gzip_comp_level 7;
        gzip_min_length 50; 
        gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/vnd.ms-fontobject application/x-font-ttf font/opentype image/svg+xml image/x-icon;
        
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
    }
EOF
Judge "写入/etc/nginx/nginx.conf"
}

function ConfigureNginxForXray(){
    domain="$1"
    xrayCertificate="$2"
    xrayCertificateKey="$3"
    randomPath="$4"
    randomPort="$5"
    proxySite=$(CheckProxySite)
    Judge "${proxySite}"
    PrintInformation "配置Nginx中..."
    ConfigureDefaultNginx
    PrintInformation "使用443端口"
    nginxConfigurationFolder="/etc/nginx/conf.d"
    mkdir -p "${nginxConfigurationFolder}"
    cat > "${nginxConfigurationFolder}/${domain}.conf" <<EOF
    server {
        listen 443 ssl http2;
        server_name ${domain};
        ssl_certificate       "${xrayCertificate}";
        ssl_certificate_key   "${xrayCertificateKey}";
        ssl_session_timeout 1d;
        ssl_session_cache shared:MozSSL:10m;
        ssl_session_tickets off;
        ssl_protocols         TLSv1.3;
        ssl_ecdh_curve        X25519:P-256:P-384:P-521;
        add_header Strict-Transport-Security "max-age=63072000" always;

                
        location / {
            proxy_pass https://${proxySite};
            proxy_ssl_server_name on;
            proxy_redirect off;
            sub_filter_once off;
            sub_filter "${proxySite}" \$server_name;
            proxy_set_header Host "${proxySite}";
            proxy_set_header Referer \$http_referer;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header User-Agent \$http_user_agent;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "zh-CN";
        }
        
        location ${randomPath} {
            proxy_redirect off;
            proxy_read_timeout 1200s;
            proxy_pass http://127.0.0.1:${randomPort};
            proxy_http_version 1.1;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }

    server {
        listen 80;
        server_name ${domain};
        return 302 https://\$server_name\$request_uri;
    }
EOF
    Judge "写入${nginxConfigurationFolder}/xray.conf"
}

function ConfigureXrayServer(){
    randomPort="$1"
    randomPath="$2"
    userId="$3"
    PrintInformation "配置Xray中..."
    cat > "/usr/local/etc/xray/config.json" <<EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "dns": {
        "servers": [
            "https+local://1.1.1.1/dns-query",
            "8.8.8.8",
            "8.8.4.4",
            "localhost"
        ]
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "outboundTag": "block",
                "domain": [
                    "geosite:category-ads-all"
                ]
            },
            {
                "type": "field",
                "outboundTag": "block",
                "ip": [
                    "geoip:private"
                ]
            },
            {
                "type": "field",
                "outboundTag": "block",
                "ip": [
                    "geoip:cn"
                ]
            }
        ]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": ${randomPort},
            "protocol": "vless",
            "tag": "vlessIn",
            "settings": {
                "clients": [
                    {
                        "id": "${userId}",
                        "level": 0,
                        "email": "tt@tt.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "${randomPath}"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 3,
                "connIdle": 180
            }
        }
    }
}
EOF
    Judge "写入/usr/local/etc/xray/config.json"
}

function RestartAll(){
    systemctl restart nginx
    Judge "重启Nginx"
    systemctl restart xray
    Judge "重启Xray"
}

function CheckServerConfiguration(){
    PrintMessage "--------------------------服务端配置------------------------------"
    cat "/usr/local/etc/xray/config.json"
}

function CheckAccessLog(){
    PrintMessage "--------------------------实时访问日志------------------------------"
    tail -f "/var/log/xray/access.log"
}

function CheckErrorLog(){
    PrintMessage "--------------------------实时错误日志------------------------------"
    tail -f "/var/log/xray/error.log"
}

function ConfigureNginxAndXray(){
    domain=$(CheckDomain)
    Judge "${domain}"
    PrintOk "域名 DNS 解析 IP 与 本机 IPv4 匹配"
    PrintInformation "生产随机端口..."
    randomPort=$(GenerateAPort)
    PrintOk "${randomPort} 将被使用"
    PrintInformation "生产伪装路径..."
    randomPath=$(GenerateAPath)
    PrintOk "${randomPath} 将被使用"
    xrayCertificateFolder="/usr/local/etc/xray/cert"
    xrayCertificate="/usr/local/etc/xray/cert/${domain}.cert"
    xrayCertificateKey="/usr/local/etc/xray/cert/${domain}.key"
    CheckPort 80
    CheckPort 443
    GenerateCertificate "${domain}" "${xrayCertificateFolder}" "${xrayCertificate}" "${xrayCertificateKey}"
    ConfigureNginxForXray "${domain}" "${xrayCertificate}" "${xrayCertificateKey}" "${randomPath}" "${randomPort}"
    userId="$(xray uuid)"
    ConfigureXrayServer "${randomPort}" "${randomPath}" "${userId}"
    RestartAll
}

function EnableBBR(){
    if [[ $( sysctl net.ipv4.tcp_congestion_control | grep bbr -c) -eq 0 ]]; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        PrintOk "启动BBR"
    else
        PrintInformation "已使用BBR"
    fi
}

function ChangeWorkingDirectory(){
    scriptDirectory="$(dirname "$0")"
    cd "${scriptDirectory}" || { PrintErrorWithBackground "Error: Unable to change directory to ${scriptDirectory}."; }
}

function Install(){
    CheckRoot
    CheckSystem
    EnablePortInFirewall
    UpgradePacakges
    DoBasicOptimization
    InstallXray
    InstallNginx
    ConfigureNginxAndXray
    EnableBBR
    PrintInformation "安装完成"
}

function Uninstall(){
    systemctl stop nginx
    Judge "停止Nginx"
    apt purge nginx -y
    Judge "删除Nginx"
    systemctl stop xray
    Judge "停止Xray"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
    Judge "删除Xray"
    rm /usr/local/bin/acme.sh
    /root/.acme.sh/acme.sh --uninstall
    Judge "卸载acme.sh"
    apt autoremove -y
    PrintOk "卸载完成"
}

function Menu() {
    PrintWithGreenPrefix "\nName" "   Xray+Nginx管理脚本"
    PrintWithGreenPrefix "Version" "0.1.0"
    PrintWithGreenPrefix "Author" " taurus"
    PrintWithGreenPrefix "Github" " https://github.com/taurusni/xray-nginx"
    PrintMessage "——————————————————————————————————————————"
    PrintWithGreenPrefix "1." "安装"
    PrintWithGreenPrefix "2." "升级 Xray core"
    PrintWithGreenPrefix "3." "卸载"
    PrintWithGreenPrefix "4." "查看 实时访问日志"
    PrintWithGreenPrefix "5." "查看 实时错误日志"
    PrintWithGreenPrefix "6." "查看 服务端配置信息"
    PrintWithGreenPrefix "7." "退出\n"
    read -rp "请输入数字:" menuNumber
    case "${menuNumber}" in
    1)
        Install
        ;;
    2)
        InstallXray
        RestartAll
        ;;
    3)
        Uninstall
        ;;
    4)
        CheckAccessLog
        ;;
    5)
        CheckErrorLog
        ;;
    6)
        CheckServerConfiguration
        ;;
    7)
        exit 0
        ;;
    *)
        PrintErrorWithBackground "请输入正确的数字"
        ;;
    esac
}

function Main(){
    ChangeWorkingDirectory
    Menu
}

Main