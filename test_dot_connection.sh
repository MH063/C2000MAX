#!/bin/sh

# ============================================================
# DoT (DNS over TLS) 连接测试脚本
# 功能：检查stubby安装、自动安装openssl、测试TCP连通性
# 使用方法: sh test_dot_connection.sh
# ============================================================

echo "=========================================="
echo "   DoT (DNS over TLS) 连接测试"
echo "=========================================="
echo ""

STUBBY_INSTALLED=0
OPENSSL_AVAILABLE=0
OPENSSL_INSTALLED=0

check_stubby() {
    echo "1. 检查 stubby 是否安装..."
    
    if [ -f /usr/bin/stubby ]; then
        echo "   ✅ stubby 已安装"
        STUBBY_INSTALLED=1
        return 0
    else
        echo "   ❌ stubby 未安装"
        STUBBY_INSTALLED=0
        return 1
    fi
}

check_openssl() {
    echo "2. 检查 openssl 是否可用..."
    
    if command -v openssl >/dev/null 2>&1; then
        echo "   ✅ openssl 命令可用"
        OPENSSL_AVAILABLE=1
        echo "   → 支持TLS验证"
        return 0
    else
        echo "   ❌ openssl 命令不可用"
        OPENSSL_AVAILABLE=0
        return 1
    fi
}

install_openssl() {
    echo ""
    echo "3. 尝试自动安装 openssl-util..."
    
    if opkg install openssl-util 2>/dev/null; then
        echo "   ✅ openssl-util 安装成功"
        OPENSSL_INSTALLED=1
        echo "   → 已自动安装（支持TLS验证）"
        return 0
    else
        echo "   ❌ openssl-util 安装失败"
        OPENSSL_INSTALLED=0
        echo "   → 请在'管理内置包'中安装 openssl-util"
        return 1
    fi
}

test_tcp_connectivity() {
    echo ""
    echo "4. 测试 TCP 连通性..."
    
    local test_servers=(
        "223.5.5.5:853:阿里DNS (DoT)"
        "119.29.29.29:853:腾讯DNS (DoT)"
        "8.8.8.8:853:Google DNS (DoT)"
        "9.9.9.9:853:Quad9 (DoT)"
        "1.1.1.1:853:Cloudflare DNS (DoT)"
    )
    
    local success_count=0
    local total_count=${#test_servers[@]}
    
    for server in "${test_servers[@]}"; do
        IFS=':' read -r ip port name <<< "$server"
        
        echo -n "   测试 $name ($ip:$port)... "
        
        if command -v nc >/dev/null 2>&1; then
            if nc -zv -w 3 "$ip" "$port" >/dev/null 2>&1; then
                echo "✅ 连接成功"
                success_count=$((success_count + 1))
            else
                echo "❌ 连接失败"
            fi
        elif command -v timeout >/dev/null 2>&1; then
            if timeout 3 bash -c "echo > /dev/tcp/$ip/$port" >/dev/null 2>&1; then
                echo "✅ 连接成功"
                success_count=$((success_count + 1))
            else
                echo "❌ 连接失败"
            fi
        else
            echo "⚠ 无法测试（缺少 nc 或 timeout）"
        fi
    done
    
    echo ""
    echo "   测试结果: $success_count/$total_count 服务器可连接"
    
    if [ $success_count -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

test_tls_handshake() {
    echo ""
    echo "5. 测试 TLS 握手..."
    
    if [ $OPENSSL_AVAILABLE -eq 0 ] && [ $OPENSSL_INSTALLED -eq 0 ]; then
        echo "   ⚠ 跳过TLS测试（openssl不可用）"
        return 1
    fi
    
    local test_server="223.5.5.5"
    local test_port="853"
    
    echo -n "   测试 TLS 连接到 $test_server:$test_port... "
    
    if timeout 5 openssl s_client -connect "$test_server:$test_port" -servername "$test_server" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        echo "✅ TLS握手成功，证书验证通过"
        return 0
    elif timeout 5 openssl s_client -connect "$test_server:$test_port" -servername "$test_server" </dev/null 2>/dev/null | grep -q "Connected"; then
        echo "⚠ TLS握手成功，但证书验证可能失败"
        return 0
    else
        echo "❌ TLS握手失败"
        return 1
    fi
}

show_summary() {
    echo ""
    echo "=========================================="
    echo "   测试结果汇总"
    echo "=========================================="
    echo ""
    
    echo "【组件状态】"
    if [ $STUBBY_INSTALLED -eq 1 ]; then
        echo "   ✓ stubby: 已安装"
    else
        echo "   ✗ stubby: 未安装"
    fi
    
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        echo "   ✓ openssl: 已安装（支持TLS验证）"
    elif [ $OPENSSL_INSTALLED -eq 1 ]; then
        echo "   ✓ openssl: 已自动安装（支持TLS验证）"
    else
        echo "   ✗ openssl: 未安装（请手动安装）"
    fi
    
    echo ""
    echo "【功能状态】"
    if [ $STUBBY_INSTALLED -eq 1 ] && ([ $OPENSSL_AVAILABLE -eq 1 ] || [ $OPENSSL_INSTALLED -eq 1 ]); then
        echo "   ✓ DoT功能: 可用"
        echo ""
        echo "建议："
        echo "   1. 配置 stubby 使用支持的 DoT 服务器"
        echo "   2. 在网络设置中启用 DNS 加密"
    else
        echo "   ✗ DoT功能: 不可用"
        echo ""
        echo "需要："
        if [ $STUBBY_INSTALLED -eq 0 ]; then
            echo "   1. 安装 stubby 包"
        fi
        if [ $OPENSSL_AVAILABLE -eq 0 ] && [ $OPENSSL_INSTALLED -eq 0 ]; then
            echo "   2. 在'管理内置包'中安装 openssl-util"
        fi
    fi
    
    echo ""
    echo "=========================================="
}

main() {
    check_stubby
    
    if ! check_openssl; then
        install_openssl
    fi
    
    test_tcp_connectivity
    
    test_tls_handshake
    
    show_summary
}

main "$@"