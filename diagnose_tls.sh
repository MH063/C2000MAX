#!/bin/sh

echo "=== TLS 连接诊断脚本 ==="
echo ""

echo "1. 检查系统时间"
echo "当前时间: $(date)"
echo "时区: $(cat /etc/TZ 2>/dev/null || echo '未设置')"
echo ""

echo "2. 检查 CA 证书"
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    echo "✓ CA 证书包存在: /etc/ssl/certs/ca-certificates.crt"
    ls -lh /etc/ssl/certs/ca-certificates.crt
elif [ -f /etc/ssl/cert.pem ]; then
    echo "✓ CA 证书包存在: /etc/ssl/cert.pem"
    ls -lh /etc/ssl/cert.pem
elif [ -d /etc/ssl/certs ]; then
    echo "✓ CA 证书目录存在: /etc/ssl/certs"
    ls -lh /etc/ssl/certs/ | head -10
else
    echo "✗ 未找到 CA 证书"
fi
echo ""

echo "3. 检查 OpenSSL 库"
if [ -f /usr/lib/libssl.so.3 ]; then
    echo "✓ libssl.so.3 存在"
    ls -lh /usr/lib/libssl.so.3
else
    echo "✗ libssl.so.3 不存在"
fi

if [ -f /usr/lib/libcrypto.so.3 ]; then
    echo "✓ libcrypto.so.3 存在"
    ls -lh /usr/lib/libcrypto.so.3
else
    echo "✗ libcrypto.so.3 不存在"
fi
echo ""

echo "4. 测试 TLS 连接（使用 wget）"
if command -v wget >/dev/null 2>&1; then
    echo "测试连接到 https://1.1.1.1 ..."
    wget --spider --timeout=5 --no-check-certificate https://1.1.1.1 2>&1 | head -5
else
    echo "wget 不可用"
fi
echo ""

echo "5. 检查 stubby 配置"
if [ -f /etc/stubby.yml ]; then
    echo "stubby.yml 配置:"
    cat /etc/stubby.yml | grep -A 5 "upstream_recursive_servers"
else
    echo "stubby.yml 不存在"
fi
echo ""

echo "6. 测试 DNS 查询（直接查询，不通过 stubby）"
if command -v nslookup >/dev/null 2>&1; then
    echo "使用默认 DNS 查询 www.baidu.com:"
    nslookup www.baidu.com
else
    echo "nslookup 不可用"
fi
echo ""

echo "7. 检查网络连接"
echo "测试 TCP 443 端口（HTTPS）到 1.1.1.1:"
if command -v nc >/dev/null 2>&1; then
    nc -zv -w 3 1.1.1.1 443 2>&1
else
    echo "nc 不可用，尝试使用 timeout + cat"
    timeout 3 cat < /dev/tcp/1.1.1.1/443 2>&1 && echo "连接成功" || echo "连接失败"
fi
echo ""

echo "8. 检查 IPv6 连接"
echo "IPv6 地址:"
ip -6 addr show 2>/dev/null | grep inet6 || echo "无 IPv6 地址"
echo ""

echo "=== 诊断完成 ==="
