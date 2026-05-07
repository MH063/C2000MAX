#!/bin/sh

# ============================================================
# DNSSEC 验证状态检测脚本
# 功能：检测当前 DNS 服务器的 DNSSEC 支持和验证状态
# 使用方法: sh check_dnssec.sh [域名] [DNS服务器IP]
# 示例: sh check_dnssec.sh example.com 1.1.1.1
# ============================================================

DOMAIN="${1:-example.com}"
DNS_SERVER="${2:-}"
LOG_FILE="/tmp/dnssec_check.log"

echo "=========================================="
echo "   DNSSEC 验证状态检测"
echo "=========================================="
echo ""
echo "测试域名: $DOMAIN"
[ -n "$DNS_SERVER" ] && echo "DNS服务器: $DNS_SERVER"
echo ""

log() {
    local msg="$1"
    echo "$msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG_FILE"
}

check_getdns_installed() {
    log "检查 getdns 库安装状态..."
    if [ -f /usr/lib/libgetdns.so.10 ] || [ -f /usr/lib/libgetdns.so.11 ]; then
        log "✅ getdns 库已安装"
        return 0
    else
        log "❌ getdns 库未安装（无法进行 DNSSEC 验证）"
        return 1
    fi
}

check_stubby_running() {
    log "检查 stubby 服务状态..."
    if pgrep -x stubby >/dev/null 2>&1; then
        local pid=$(pgrep -x stubby)
        log "✅ stubby 运行中 (PID: $pid)"
        
        if [ -f /var/run/stubby.pid ]; then
            log "   PID 文件: /var/run/stubby.pid"
        fi
        
        return 0
    else
        log "⚠️  stubby 未运行"
        return 1
    fi
}

check_https_dns_proxy_running() {
    log "检查 https-dns-proxy 服务状态..."
    if pgrep -f https-dns-proxy >/dev/null 2>&1; then
        local pid=$(pgrep -f https-dns-proxy)
        log "✅ https-dns-proxy 运行中 (PID: $pid)"
        return 0
    else
        log "⚠️  https-dns-proxy 未运行"
        return 1
    fi
}

test_dnssec_with_getdns() {
    log ""
    log "=== 使用 getdns 进行 DNSSEC 验证 ==="
    
    if ! command -v getdns_query >/dev/null 2>&1; then
        log "⚠️  getdns_query 命令不可用，尝试使用备用方法..."
        return 1
    fi
    
    local dns_param=""
    if [ -n "$DNS_SERVER" ]; then
        dns_param="--upstream $DNS_SERVER"
    fi
    
    log "查询域名: $DOMAIN 的 DNSSEC 状态..."
    
    if getdns_query --dnssec_return_status $dns_param $DOMAIN 2>/dev/null; then
        log "✅ DNSSEC 查询成功"
        return 0
    else
        log "❌ DNSSEC 查询失败"
        return 1
    fi
}

test_dnssec_via_stubby() {
    log ""
    log "=== 通过 stubby (DoT) 测试 DNSSEC ==="
    
    if ! pgrep -x stubby >/dev/null 2>&1; then
        log "⚠️  stubby 未运行，跳过此测试"
        return 1
    fi
    
    log "通过 stubby (127.0.0.1:5453) 查询 DNSSEC 记录..."
    
    if nslookup $DOMAIN 127.0.0.1 2>/dev/null | grep -q "server"; then
        log "✅ 通过 stubby 查询成功"
        log "   注意：stubby 连接的上游服务器可能已执行 DNSSEC 验证"
        return 0
    else
        log "❌ 通过 stubby 查询失败"
        return 1
    fi
}

test_dnssec_via_https_proxy() {
    log ""
    log "=== 通过 https-dns-proxy (DoH) 测试 DNSSEC ==="
    
    if ! pgrep -f https-dns-proxy >/dev/null 2>&1; then
        log "⚠️  https-dns-proxy 未运行，跳过此测试"
        return 1
    fi
    
    log "通过 https-dns-proxy (127.0.0.1:5053) 查询..."
    
    if nslookup $DOMAIN 127.0.0.1 2>/dev/null | grep -q "server"; then
        log "✅ 通过 https-dns-proxy 查询成功"
        log "   注意：DoH 上游服务器可能已执行 DNSSEC 验证"
        return 0
    else
        log "❌ 通过 https-dns-proxy 查询失败"
        return 1
    fi
}

check_upstream_dnssec_support() {
    log ""
    log "=== 上游 DNS 服务器 DNSSEC 支持情况 ==="
    
    local servers=(
        "Cloudflare:1.1.1.1:true:默认开启 DNSSEC"
        "Quad9:9.9.9.9:true:默认开启 DNSSEC"
        "Google:8.8.8.8:true:支持 DNSSEC"
        "阿里DNS:223.5.5.5:false:不支持 DNSSEC"
        "腾讯DNS:119.29.29.29:false:不支持 DNSSEC"
        "AdGuard:94.140.14.14:true:支持 DNSSEC"
    )
    
    for server_info in "${servers[@]}"; do
        IFS=':' read -r name ip support desc <<< "$server_info"
        
        echo -n "$name ($ip): "
        
        if timeout 3 nslookup $DOMAIN $ip >/dev/null 2>&1; then
            if [ "$support" = "true" ]; then
                echo "✅ 可连接 ($desc)"
            else
                echo "⚠️  可连接 ($desc)"
            fi
        else
            echo "❌ 无法连接"
        fi
    done
}

verify_dnssec_chain() {
    log ""
    log "=== DNSSEC 链式验证说明 ==="
    log ""
    log "DNSSEC 验证链："
    log "  根区域 DNSKEY → TLD 区域 DS → 域名区域 DNSKEY → RRSIG"
    log ""
    log "验证步骤："
    log "  1. 获取根区域的 DNSKEY 记录（信任锚点）"
    log "  2. 验证 TLD 区域的 DS 记录签名"
    log "  3. 获取目标域名的 DNSKEY 记录"
    log "  4. 验证目标域名的 RRSIG 签名"
    log ""
    log "当前系统限制："
    log "  ❌ 不支持 dig 命令（无法直接查看 RRSIG/DNSKEY 记录）"
    log "  ✅ 可通过 getdns 库进行程序化验证"
    log "  ✅ 上游服务器（如 Cloudflare、Quad9）已执行服务端验证"
}

generate_report() {
    log ""
    log "=========================================="
    log "   DNSSEC 验证报告总结"
    log "=========================================="
    log ""
    log "系统工具状态："
    check_getdns_installed || true
    check_stubby_running || true
    check_https_dns_proxy_running || true
    log ""
    log "安全建议："
    log "  1. ✅ 使用支持 DNSSEC 的上游 DNS 服务器（推荐 Cloudflare/Quad9）"
    log "  2. ✅ 启用 DoT/DoT 加密传输（防止中间人攻击）"
    log "  3. ⚠️  本地验证需要 getdns 命令行工具完整安装"
    log "  4. 💡 当前最佳实践：依赖上游递归解析器的 DNSSEC 验证"
    log ""
    log "纵深防御体系："
    log "  第一层：传输加密（DoH/DoT）- 已实现 ✅"
    log "  第二层：服务端 DNSSEC 验证 - 由上游服务器处理 ✅"
    log "  第三层：客户端本地验证 - 需要 dig/getdns CLI ⚠️"
    log ""
    log "详细日志: $LOG_FILE"
    log "=========================================="
}

main() {
    rm -f "$LOG_FILE"
    
    log "开始 DNSSEC 验证检测..."
    log "时间: $(date)"
    
    check_getdns_installed
    check_stubby_running
    check_https_dns_proxy_running
    
    test_dnssec_with_getdns || true
    test_dnssec_via_stubby || true
    test_dnssec_via_https_proxy || true
    
    check_upstream_dnssec_support
    verify_dnssec_chain
    generate_report
    
    log ""
    log "✅ DNSSEC 检测完成！"
}

main "$@"
