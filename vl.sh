#!/bin/bash
# =========================
# VLESS-WS + Argo 超轻量脚本
# 适合低配 VPS
# =========================

export LANG=en_US.UTF-8

# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"

red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"

GITHUB_URL="https://raw.githubusercontent.com/gaodashang167/vl/main/vl.sh"
LOCAL_SCRIPT="${work_dir}/hu.sh"

export vless_port=${PORT:-8001}

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态
check_service() {
    local service_name=$1
    local service_file=$2
    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }
    if command_exists apk; then
        rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
    else
        systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
    fi
    return $?
}

check_singbox() { check_service "sing-box" "${work_dir}/${server_name}"; }
check_argo() { check_service "argo" "${work_dir}/argo"; }

# 包管理
manage_packages() {
    if [ $# -lt 2 ]; then red "Unspecified package name or action"; return 1; fi
    action=$1
    shift
    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then green "${package} already installed"; continue; fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then dnf install -y "$package"
            elif command_exists yum; then yum install -y "$package"
            elif command_exists apk; then apk update && apk add "$package"
            else red "Unknown system!"; return 1; fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then yellow "${package} is not installed"; continue; fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then apk del "$package"
            else red "Unknown system!"; return 1; fi
        fi
    done
}

# 获取IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then echo "[$(ipv6)]"
    elif curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then echo "[$(ipv6)]"
    else
        resp=$(curl -sm 8 "https://status.eooce.com/api/$ip" | jq -r '.status' 2>/dev/null)
        if [ "$resp" = "Available" ]; then echo "$ip"; else v6=$(ipv6); [ -n "$v6" ] && echo "[$v6]" || echo "$ip"; fi
    fi
}

# 安装Singbox
install_singbox() {
    clear
    purple "正在安装 sing-box (超轻量版)，请稍后..."
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo
    
    uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # 超精简配置（无日志、无NTP）
cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-ws",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": ""
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vless",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
    green "配置已生成: VLESS-WS (端口 $vless_port)"
}

# Systemd服务
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://127.0.0.1:$vless_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ]; then
        yum install -y chrony >/dev/null 2>&1
        systemctl start chronyd >/dev/null 2>&1
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    systemctl daemon-reload
    systemctl enable sing-box argo >/dev/null 2>&1
    systemctl start sing-box argo
}

# OpenRC服务
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run
description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF
    cat > /etc/init.d/argo << EOF
#!/sbin/openrc-run
description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://127.0.0.1:$vless_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF
    chmod +x /etc/init.d/sing-box /etc/init.d/argo
    rc-update add sing-box default >/dev/null 2>&1
    rc-update add argo default >/dev/null 2>&1
}

# 获取信息
get_info() {
    if [ -z "$uuid" ] && [ -f "$config_dir" ]; then
        if command_exists jq; then
            uuid=$(jq -r '.inbounds[0].users[0].uuid' "$config_dir")
        else
            uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
        fi
    fi
    
    yellow "\n正在获取节点信息...\n"
    server_ip=$(get_realip)
    isp=$(curl -s --max-time 2 https://ipapi.co/json 2>/dev/null | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | sed 's/ /_/g' || echo "VPS")
    
    # Argo 域名获取
    argodomain=""
    [ -f "${work_dir}/tunnel.yml" ] && argodomain=$(grep "hostname:" "${work_dir}/tunnel.yml" | head -1 | awk '{print $2}' | tr -d ' "')
    
    if [ -z "$argodomain" ]; then
        if [ -f "${work_dir}/argo.log" ]; then
            for i in {1..3}; do
                argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
                [ -n "$argodomain" ] && break
                sleep 1
            done
        fi
        if [ -z "$argodomain" ]; then
            purple "临时域名获取中..."
            restart_argo >/dev/null 2>&1 && sleep 5
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
        fi
    else
        green "\n检测到固定隧道: ${argodomain}"
    fi
    
    if [ -z "$argodomain" ]; then
        red "Argo域名获取失败"
        vless_link=""
    else
        vless_link="vless://${uuid}@www.visa.com:443?encryption=none&security=tls&sni=${argodomain}&type=ws&host=${argodomain}&path=%2Fvless%3Fed%3D2560#${isp}-Argo"
    fi

    clear
    echo ""
    green "==================== 节点信息 ====================\n"
    if [ -n "$vless_link" ]; then
        purple "VLESS-WS-TLS 节点:"
        echo "${vless_link}"
        green "\nArgo域名: ${argodomain}"
        green "本地端口: ${vless_port}"
    else
        red "节点生成失败，请检查 Argo 服务"
    fi
    echo ""
    
    cat > ${work_dir}/url.txt << EOF
${vless_link}
EOF
    
    green "节点已保存: ${work_dir}/url.txt"
    yellow "\n提示: VLESS-WS 性能更好，CPU 占用更低！\n"
}

# 服务管理
manage_service() {
    local n=$1; local a=$2
    if command_exists rc-service; then
        rc-service "$n" "$a"
    else
        [ "$a" == "restart" ] && systemctl daemon-reload
        systemctl "$a" "$n"
    fi
}
start_singbox() { manage_service "sing-box" "start"; }
stop_singbox() { manage_service "sing-box" "stop"; }
restart_singbox() { manage_service "sing-box" "restart"; }
start_argo() { manage_service "argo" "start"; }
stop_argo() { manage_service "argo" "stop"; }
restart_argo() { manage_service "argo" "restart"; }

# 卸载
uninstall_singbox() {
    reading "确定要卸载吗? (y/n): " choice
    [[ "$choice" != "y" && "$choice" != "Y" ]] && purple "取消卸载" && return
    yellow "正在卸载..."
    if command_exists rc-service; then
        rc-service sing-box stop; rc-service argo stop
        rc-update del sing-box default; rc-update del argo default
        rm /etc/init.d/sing-box /etc/init.d/argo
    else
        systemctl stop sing-box argo; systemctl disable sing-box argo
        rm /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service
        systemctl daemon-reload
    fi
    rm -rf "${work_dir}" /usr/bin/hu
    green "\n卸载成功\n" && exit 0
}

# 创建快捷指令
create_shortcut() {
    yellow "\n配置快捷指令 hu..."
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL" 2>/dev/null
    chmod +x "$LOCAL_SCRIPT"
    
    cat > "/usr/bin/hu" << EOF
#!/bin/bash
if [ -s "$LOCAL_SCRIPT" ]; then
    bash "$LOCAL_SCRIPT" \$1
else
    echo -e "\033[1;33m本地脚本丢失，尝试从 GitHub 重新下载...\033[0m"
    mkdir -p "$work_dir"
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL"
    chmod +x "$LOCAL_SCRIPT"
    [ -s "$LOCAL_SCRIPT" ] && bash "$LOCAL_SCRIPT" \$1 || echo -e "\033[1;91m下载失败\033[0m"
fi
EOF
    chmod +x "/usr/bin/hu"
    green "\n>>> 快捷指令 hu 创建成功！<<<\n"
}

# Alpine适配
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# Argo固定隧道配置
setup_argo_fixed() {
    clear
    yellow "\n固定隧道配置 (端口: ${vless_port})\n"
    reading "域名: " argo_domain
    reading "Token/Json: " argo_auth
    [ -z "$argo_domain" ] || [ -z "$argo_auth" ] && red "不能为空" && return
    
    # 停止服务
    if command_exists rc-service; then
        rc-service argo stop >/dev/null 2>&1
    else
        systemctl stop argo >/dev/null 2>&1
    fi
    
    if [[ $argo_auth =~ TunnelSecret ]]; then
        # JSON 模式
        echo "$argo_auth" > "${work_dir}/tunnel.json"
        TUNNEL_ID=$(cut -d\" -f12 <<< "$argo_auth")
        cat > "${work_dir}/tunnel.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${work_dir}/tunnel.json
protocol: http2
ingress:
  - hostname: $argo_domain
    service: http://127.0.0.1:${vless_port}
    originRequest: 
      noTLSVerify: true
  - service: http_status:404
EOF
        
        if command_exists rc-service; then
            cat > /etc/init.d/argo << 'EOFARGO'
#!/sbin/openrc-run
description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1 > /etc/sing-box/argo.log'"
command_background=true
pidfile="/var/run/argo.pid"
EOFARGO
            chmod +x /etc/init.d/argo
            rc-service argo start
        else
            cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl restart argo
        fi
        
    elif [[ $argo_auth =~ ^[A-Za-z0-9_-]{100,}$ ]]; then
        # Token 模式
        echo "hostname: $argo_domain" > "${work_dir}/tunnel.yml"
        
        if command_exists rc-service; then
            cat > /etc/init.d/argo << EOFARGO
#!/sbin/openrc-run
description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1 > /etc/sing-box/argo.log'"
command_background=true
pidfile="/var/run/argo.pid"
EOFARGO
            chmod +x /etc/init.d/argo
            rc-service argo start
        else
            cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl restart argo
        fi
    else
        red "Token/Json 格式不正确"
        return 1
    fi

    sleep 3
    
    # 检查状态
    if command_exists rc-service; then
        if rc-service argo status | grep -q "started"; then
            green "\n✓ Argo 固定隧道启动成功"
        else
            red "\n✗ Argo 启动失败，查看日志: cat /etc/sing-box/argo.log"
            return 1
        fi
    else
        if systemctl is-active argo >/dev/null 2>&1; then
            green "\n✓ Argo 固定隧道启动成功"
        else
            red "\n✗ Argo 启动失败，查看日志: journalctl -u argo -n 50"
            return 1
        fi
    fi
    
    green "配置完成，正在刷新信息..." && get_info
}

# 主菜单
menu() {
    singbox_status=$(check_singbox 2>/dev/null); argo_status=$(check_argo 2>/dev/null)
    clear
    purple "\n=== VLESS-WS + Argo 超轻量脚本 ===\n"
    echo -e "Argo: ${argo_status} | Sing-box: ${singbox_status}\n"
    green "1. 安装"
    red "2. 卸载"
    green "3. 查看节点"
    green "4. 配置固定隧道"
    green "5. 重启服务"
    red "0. 退出"
    reading "\n请选择: " choice
}

while true; do
    menu
    case "${choice}" in
        1)
            if check_singbox >/dev/null 2>&1; then 
                yellow "已安装"
                create_shortcut
            else
                manage_packages install jq openssl coreutils
                install_singbox
                if command_exists systemctl; then 
                    main_systemd_services
                else 
                    alpine_openrc_services
                    change_hosts
                    rc-service sing-box restart
                    rc-service argo restart
                fi
                sleep 5
                get_info
                create_shortcut
            fi 
            ;;
        2) uninstall_singbox ;;
        3) get_info ;;
        4) setup_argo_fixed ;;
        5) restart_singbox && restart_argo && green "\n重启成功\n" ;;
        0) exit 0 ;;
        *) red "无效选项" ;;
    esac
    read -n 1 -s -r -p "按任意键继续..."
done
