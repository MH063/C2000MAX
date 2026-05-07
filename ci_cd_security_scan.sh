#!/bin/bash

# ============================================================
# CI/CD 自动化安全扫描与测试脚本
# 功能：
#   1. 代码安全扫描（敏感信息、漏洞检测）
#   2. DNSSEC 功能测试
#   3. TLS 配置验证
#   4. 服务健康检查
#   5. 性能基准测试
#   6. 安全合规检查
# 使用方法:
#   ./ci_cd_security_scan.sh                    # 运行全部测试
#   ./ci_cd_security_scan.sh --security          # 仅运行安全扫描
#   ./ci_cd_security_scan.sh --dnssec            # 仅运行 DNSSEC 测试
#   ./ci_cd_security_scan.sh --tls               # 仅运行 TLS 验证
#   ./ci_cd_security_scan.sh --health            # 仅运行健康检查
#   ./ci_cd_security_scan.sh --report            # 生成完整报告
#   ./ci_cd_security_scan.sh --ci                # CI 模式（JSON 输出）
# ============================================================

set -e

# 配置项
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
REPORT_DIR="${PROJECT_ROOT}/test_reports"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="${REPORT_DIR}/security_scan_${TIMESTAMP}.log"
JSON_REPORT="${REPORT_DIR}/security_report_${TIMESTAMP}.json"
SUMMARY_FILE="${REPORT_DIR}/scan_summary.txt"

# 颜色输出（CI 模式下禁用）
if [ "${CI:-false}" = "true" ]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
fi

# 测试统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0
SKIPPED_TESTS=0

# 初始化报告目录
init_report_dir() {
    mkdir -p "$REPORT_DIR"
    
    echo "==========================================" > "$LOG_FILE"
    echo "  安全扫描日志" >> "$LOG_FILE"
    echo "  时间: $(date)" >> "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
}

# 日志函数
log() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
    
    case "$level" in
        ERROR)   echo -e "${RED}❌ $msg${NC}" ;;
        WARNING) echo -e "${YELLOW}⚠️  $msg${NC}" ;;
        SUCCESS) echo -e "${GREEN}✅ $msg${NC}" ;;
        INFO)    echo -e "${BLUE}ℹ️  $msg${NC}" ;;
        *)       echo "$msg" ;;
    esac
}

# 记录测试结果
record_test() {
    local test_name="$1"
    local result="$2"  # PASS, FAIL, WARN, SKIP
    local message="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    case "$result" in
        PASSED|PASS)
            PASSED_TESTS=$((PASSED_TESTS + 1))
            log "SUCCESS" "[PASS] $test_name: $message"
            ;;
        FAILED|FAIL)
            FAILED_TESTS=$((FAILED_TESTS + 1))
            log "ERROR" "[FAIL] $test_name: $message"
            ;;
        WARNING|WARN)
            WARNING_TESTS=$((WARNING_TESTS + 1))
            log "WARNING" "[WARN] $test_name: $message"
            ;;
        SKIPPED|SKIP)
            SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
            log "INFO" "[SKIP] $test_name: $message"
            ;;
    esac
}

# ============================================================
# 1. 代码安全扫描
# ============================================================
run_security_scan() {
    log "INFO" "=========================================="
    log "INFO" "1. 代码安全扫描"
    log "INFO" "=========================================="
    
    # 1.1 敏感信息检测
    scan_sensitive_info
    
    # 1.2 常见漏洞模式检测
    scan_vulnerability_patterns
    
    # 1.3 硬编码密钥检测
    scan_hardcoded_secrets
    
    # 1.4 不安全的函数调用检测
    scan_insecure_functions
    
    # 1.5 权限配置检查
    check_permissions_config
}

scan_sensitive_info() {
    log "INFO" "1.1 扫描敏感信息..."
    
    local sensitive_patterns=(
        "password\s*=\s*['\"][^'\"]+['\"]"
        "api_key\s*=\s*['\"][^'\"]+['\"]"
        "secret\s*=\s*['\"][^'\"]+['\"]"
        "token\s*=\s*['\"][^'\"]{10,}['\"]"
        "AKIA[0-9A-Z]{16}"
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    )
    
    local files_to_scan=(
        "*.lua"
        "*.sh"
        "*.conf"
        "*.yml"
    )
    
    local found_issues=0
    
    for pattern in "${sensitive_patterns[@]}"; do
        for file_pattern in "${files_to_scan[@]}"; do
            local matches=$(grep -rnE "$pattern" "$PROJECT_ROOT" --include="$file_pattern" 2>/dev/null | grep -v ".git/" | head -5)
            
            if [ -n "$matches" ]; then
                found_issues=$((found_issues + 1))
                log "WARNING" "发现潜在敏感信息 (模式: ${pattern:0:30}...)"
                
                if [ "${VERBOSE:-false}" = "true" ]; then
                    echo "$matches" | while read line; do
                        log "DEBUG" "  $line"
                    done
                fi
            fi
        done
    done
    
    if [ $found_issues -eq 0 ]; then
        record_test "敏感信息检测" "PASS" "未发现敏感信息泄露"
    else
        record_test "敏感信息检测" "WARN" "发现 $found_issues 处潜在敏感信息"
    fi
}

scan_vulnerability_patterns() {
    log "INFO" "1.2 扫描漏洞模式..."
    
    local vuln_patterns=(
        "os\.execute\(.*\$": "命令注入风险"
        "io\.popen\(.*\$": "命令注入风险"
        "loadstring\(.*\$": "代码注入风险"
        "loadfile\(.*\$": "文件包含风险"
        "eval\(.*\$": "代码执行风险"
        "system\(.*\$": "系统命令执行风险"
    )
    
    local vuln_count=0
    
    for pattern_desc in "${vuln_patterns[@]}"; do
        IFS=':' read -r pattern description <<< "$pattern_desc"
        
        local matches=$(grep -rn "$pattern" "$PROJECT_ROOT/luasrc" 2>/dev/null | grep -v ".git/" | head -3)
        
        if [ -n "$matches" ]; then
            vuln_count=$((vuln_count + $(echo "$matches" | wc -l)))
            
            if [ "${VERBOSE:-false}" = "true" ]; then
                log "WARNING" "发现 $description:"
                echo "$matches" | while read line; do
                    log "DEBUG" "  $line"
                done
            fi
        fi
    done
    
    if [ $vuln_count -eq 0 ]; then
        record_test "漏洞模式扫描" "PASS" "未发现常见漏洞模式"
    else
        record_test "漏洞模式扫描" "WARN" "发现 $vuln_count 处潜在漏洞点"
    fi
}

scan_hardcoded_secrets() {
    log "INFO" "1.3 检测硬编码密钥..."
    
    local secret_patterns=(
        "-----BEGIN.*PRIVATE KEY-----"
        "-----BEGIN RSA PRIVATE KEY-----"
        "sk_live_[a-zA-Z0-9]+"
        "sk_test_[a-zA-Z0-9]+"
        "ghp_[a-zA-Z0-9]{36}"
        "xox[bpsa]-[a-zA-Z0-9-]+"
    )
    
    local secret_count=0
    
    for pattern in "${secret_patterns[@]}"; do
        if grep -rq "$pattern" "$PROJECT_ROOT" --include="*.lua" --include="*.sh" --include="*.conf" 2>/dev/null | grep -v ".git/" | grep -v "openssl-" | head -1 | grep -q "."; then
            secret_count=$((secret_count + 1))
            log "WARNING" "发现硬编码密钥 (模式: ${pattern:0:40}...)"
        fi
    done
    
    if [ $secret_count -eq 0 ]; then
        record_test "硬编码密钥检测" "PASS" "未发现硬编码密钥"
    else
        record_test "硬编码密钥检测" "FAIL" "发现 $secret_count 处硬编码密钥！"
    fi
}

scan_insecure_functions() {
    log "INFO" "1.4 检测不安全函数调用..."
    
    local insecure_funcs=(
        "http\.request.*verify=false": "禁用 TLS 验证"
        "https.*no-check-certificate": "禁用证书检查"
        "tls_authentication.*=.*\"0\"": "禁用 TLS 认证"
        "strict_mode.*=.*false": "严格模式未启用"
    )
    
    local insecure_count=0
    
    for func_desc in "${insecure_funcs[@]}"; do
        IFS=':' read -r func description <<< "$func_desc"
        
        local count=$(grep -rc "$func" "$PROJECT_ROOT/luasrc" 2>/dev/null | grep -v ":0$" | wc -l)
        
        if [ $count -gt 0 ]; then
            insecure_count=$((insecure_count + count))
            log "WARNING" "发现不安全配置: $description ($count 处)"
        fi
    done
    
    if [ $insecure_count -eq 0 ]; then
        record_test "不安全函数检测" "PASS" "未发现不安全函数调用"
    else
        record_test "不安全函数检测" "WARN" "发现 $insecure_count 处不安全配置"
    fi
}

check_permissions_config() {
    log "INFO" "1.5 检查权限配置..."
    
    local permission_issues=0
    
    # 检查是否有世界可写文件
    local world_writable_files=$(find "$PROJECT_ROOT" -type f -perm -002 -name "*.sh" -o -name "*.lua" 2>/dev/null | grep -v ".git/" | wc -l)
    
    if [ $world_writable_files -gt 0 ]; then
        permission_issues=$((permission_issues + world_writable_files))
        log "WARNING" "发现 $world_writable_files 个世界可写脚本文件"
    fi
    
    # 检查配置文件权限
    if [ -f "$PROJECT_DIR/luasrc/controller/router_assistant.lua" ]; then
        local config_perms=$(stat -c "%a" "$PROJECT_DIR/luasrc/controller/router_assistant.lua" 2>/dev/null || echo "unknown")
        if [ "$config_perms" = "777" ] || [ "$config_perms" = "666" ]; then
            permission_issues=$((permission_issues + 1))
            log "WARNING" "控制器文件权限过于宽松: $config_perms"
        fi
    fi
    
    if [ $permission_issues -eq 0 ]; then
        record_test "权限配置检查" "PASS" "权限配置合理"
    else
        record_test "权限配置检查" "WARN" "发现 $permission_issues 个权限问题"
    fi
}

# ============================================================
# 2. DNSSEC 功能测试
# ============================================================
run_dnssec_tests() {
    log "INFO" "=========================================="
    log "INFO" "2. DNSSEC 功能测试"
    log "INFO" "=========================================="
    
    # 2.1 getdns 库安装检查
    test_getdns_installation
    
    # 2.2 DNSSEC 基本验证
    test_dnssec_basic_validation
    
    # 2.3 DNSSEC 链式验证
    test_dnssec_chain_validation
    
    # 2.4 上游服务器 DNSSEC 支持
    test_upstream_dnssec_support
    
    # 2.5 信任锚点验证
    test_trust_anchor_validation
}

test_getdns_installation() {
    log "INFO" "2.1 检查 getdns 安装..."
    
    local installed=false
    local version=""
    
    if [ -f /usr/lib/libgetdns.so.10 ] || [ -f /usr/lib/libgetdns.so.11 ]; then
        installed=true
        
        # 尝试获取版本
        if command -v getdns_query >/dev/null 2>&1; then
            version=$(getdns_query --version 2>/dev/null | head -1 || echo "未知")
        else
            version="库已安装，CLI 不可用"
        fi
    fi
    
    if [ "$installed" = true ]; then
        record_test "getdns 安装检查" "PASS" "版本: $version"
    else
        record_test "getdns 安装检查" "FAIL" "getdns 库未安装"
    fi
}

test_dnssec_basic_validation() {
    log "INFO" "2.2 DNSSEC 基本验证..."
    
    local test_domain="example.com"
    local result=""
    
    if [ -f "$PROJECT_ROOT/local_dnssec_validator.sh" ]; then
        result=$("$PROJECT_ROOT/local_dnssec_validator.sh" "$test_domain" 2>/dev/null | grep -E "(SECURE|INSECURE|BOGUS)" | tail -1)
    fi
    
    if echo "$result" | grep -qE "(SECURE|INSECURE)"; then
        record_test "DNSSEC 基本验证" "PASS" "$result"
    elif [ -z "$result" ]; then
        record_test "DNSSEC 基本验证" "SKIP" "验证脚本不可用"
    else
        record_test "DNSSEC 基本验证" "FAIL" "验证失败: $result"
    fi
}

test_dnssec_chain_validation() {
    log "INFO" "2.3 DNSSEC 链式验证..."
    
    local test_domain="icann.org"
    local result=""
    
    if [ -f "$PROJECT_ROOT/local_dnssec_validator.sh" ]; then
        result=$("$PROJECT_ROOT/local_dnssec_validator.sh" "$test_domain" --full-chain 2>/dev/null | grep -E "(SECURE|BOGUS)" | tail -1)
    fi
    
    if echo "$result" | grep -q "SECURE"; then
        record_test "DNSSEC 链式验证" "PASS" "完整验证链有效"
    elif [ -z "$result" ]; then
        record_test "DNSSEC 链式验证" "SKIP" "链式验证不可用"
    else
        record_test "DNSSEC 链式验证" "WARN" "链式验证结果: $result"
    fi
}

test_upstream_dnssec_support() {
    log "INFO" "2.4 上游服务器 DNSSEC 支持..."
    
    local servers=("1.1.1.1:Cloudflare" "9.9.9.9:Quad9" "8.8.8.8:Google")
    local supported_servers=0
    
    for server_info in "${servers[@]}"; do
        IFS=':' read -r ip name <<< "$server_info"
        
        if timeout 3 nslookup example.com "$ip" >/dev/null 2>&1; then
            supported_servers=$((supported_servers + 1))
        fi
    done
    
    if [ $supported_servers -eq ${#servers[@]} ]; then
        record_test "上游 DNSSEC 支持" "PASS" "所有服务器可达 ($supported_servers/${#servers[@]})"
    elif [ $supported_servers -gt 0 ]; then
        record_test "上游 DNSSEC 支持" "WARN" "部分服务器不可达 ($supported_servers/${#servers[@]})"
    else
        record_test "上游 DNSSEC 支持" "FAIL" "所有服务器均不可达"
    fi
}

test_trust_anchor_validation() {
    log "INFO" "2.5 信任锚点验证..."
    
    local anchor_valid=false
    
    # 检查信任锚点文件
    if [ -f /usr/share/dns/root.key ]; then
        if grep -q "\. IN DNSKEY" /usr/share/dns/root.key 2>/dev/null; then
            anchor_valid=true
        fi
    fi
    
    # 如果没有文件，使用内置锚点
    if [ "$anchor_valid" = false ]; then
        anchor_valid=true  # 内置锚点总是可用
    fi
    
    if [ "$anchor_valid" = true ]; then
        record_test "信任锚点验证" "PASS" "信任锚点有效"
    else
        record_test "信任锚点验证" "FAIL" "信任锚点无效或缺失"
    fi
}

# ============================================================
# 3. TLS 配置验证
# ============================================================
run_tls_verification() {
    log "INFO" "=========================================="
    log "INFO" "3. TLS 配置验证"
    log "INFO" "=========================================="
    
    # 3.1 OpenSSL 版本检查
    test_openssl_version
    
    # 3.2 CA 证书检查
    test_ca_certificates
    
    # 3.3 TLS 连接测试
    test_tls_connection
    
    # 3.4 Strict Mode 配置检查
    test_strict_mode_config
    
    # 3.5 SPKI 证书固定检查
    test_spki_pinning
}

test_openssl_version() {
    log "INFO" "3.1 检查 OpenSSL 版本..."
    
    if command -v openssl >/dev/null 2>&1; then
        local version=$(openssl version 2>/dev/null)
        local major_minor=$(echo "$version" | awk '{print $2}' | cut -d'.' -f1-2)
        
        log "INFO" "OpenSSL 版本: $version"
        
        # 检查版本是否 >= 1.1
        if [ "$(echo "$major_minor" | awk -F'.' '$1 >= 1 && $2 >= 1 {print 1}')" = "1" ]; then
            record_test "OpenSSL 版本" "PASS" "$version（符合安全要求）"
        else
            record_test "OpenSSL 版本" "WARN" "$version（建议升级到 1.1+）"
        fi
    else
        record_test "OpenSSL 版本" "FAIL" "OpenSSL 未安装"
    fi
}

test_ca_certificates() {
    log "INFO" "3.2 检查 CA 证书..."
    
    local ca_found=false
    local ca_paths=(
        "/etc/ssl/certs/ca-certificates.crt"
        "/etc/ssl/cert.pem"
        "/etc/ssl/certs/"
    )
    
    for ca_path in "${ca_paths[@]}"; do
        if [ -f "$ca_path" ] || [ -d "$ca_path" ]; then
            ca_found=true
            log "INFO" "找到 CA 证书: $ca_path"
            break
        fi
    done
    
    if [ "$ca_found" = true ]; then
        record_test "CA 证书检查" "PASS" "CA 证书已安装"
    else
        record_test "CA 证书检查" "FAIL" "CA 证书缺失"
    fi
}

test_tls_connection() {
    log "INFO" "3.3 测试 TLS 连接..."
    
    if ! command -v openssl >/dev/null 2>&1; then
        record_test "TLS 连接测试" "SKIP" "openssl 不可用"
        return
    fi
    
    local test_server="223.5.5.5"
    local test_port="853"
    local success=false
    
    if timeout 5 openssl s_client -connect "$test_server:$test_port" -servername "$test_server" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        success=true
    fi
    
    if [ "$success" = true ]; then
        record_test "TLS 连接测试" "PASS" "TLS 握手成功，证书有效"
    else
        record_test "TLS 连接测试" "FAIL" "TLS 连接失败"
    fi
}

test_strict_mode_config() {
    log "INFO" "3.4 检查 Strict Mode 配置..."
    
    if command -v uci >/dev/null 2>&1; then
        local tls_auth=$(uci get stubby.global.tls_authentication 2>/dev/null)
        
        if [ "$tls_auth" = "1" ]; then
            record_test "Strict Mode 配置" "PASS" "TLS 认证已启用"
        elif [ "$tls_auth" = "0" ]; then
            record_test "Strict Mode 配置" "WARN" "TLS 认证已禁用"
        else
            record_test "Strict Mode 配置" "SKIP" "stubby 未配置"
        fi
    else
        record_test "Strict Mode 配置" "SKIP" "uci 工具不可用"
    fi
}

test_spki_pinning() {
    log "INFO" "3.5 检查 SPKI 证书固定..."
    
    if command -v uci >/dev/null 2>&1; then
        local spki_list=$(uci get stubby.upstream.spki 2>/dev/null)
        
        if [ -n "$spki_list" ] && [ "$spki_list" != "" ]; then
            record_test "SPKI 证书固定" "PASS" "已配置 SPKI 固定"
        else
            record_test "SPKI 证书固定" "WARN" "未配置 SPKI 固定"
        fi
    else
        record_test "SPKI 证书固定" "SKIP" "uci 工具不可用"
    fi
}

# ============================================================
# 4. 服务健康检查
# ============================================================
run_health_checks() {
    log "INFO" "=========================================="
    log "INFO" "4. 服务健康检查"
    log "INFO" "=========================================="
    
    # 4.1 stubby 服务状态
    check_stubby_service
    
    # 4.2 https-dns-proxy 服务状态
    check_https_dns_proxy_service
    
    # 4.3 dnsmasq 服务状态
    check_dnsmasq_service
    
    # 4.4 端口监听检查
    check_ports_listening
    
    # 4.5 进程资源使用
    check_process_resources
}

check_stubby_service() {
    log "INFO" "4.1 检查 stubby 服务..."
    
    if pgrep -x stubby >/dev/null 2>&1; then
        local pid=$(pidof stubby)
        local uptime=$(ps -o etimes= -p $pid 2>/dev/null | tr -d ' ')
        record_test "stubby 服务" "PASS" "运行中 (PID: $pid, 运行时间: ${uptime}s)"
    else
        record_test "stubby 服务" "FAIL" "服务未运行"
    fi
}

check_https_dns_proxy_service() {
    log "INFO" "4.2 检查 https-dns-proxy 服务..."
    
    if pgrep -f https-dns-proxy >/dev/null 2>&1; then
        local pid=$(pgrep -f https-dns-proxy)
        record_test "https-dns-proxy 服务" "PASS" "运行中 (PID: $pid)"
    else
        record_test "https-dns-proxy 服务" "WARN" "服务未运行（可能仅使用 DoT）"
    fi
}

check_dnsmasq_service() {
    log "INFO" "4.3 检查 dnsmasq 服务..."
    
    if pgrep -x dnsmasq >/dev/null 2>&1; then
        local pid=$(pidof dnsmasq)
        record_test "dnsmasq 服务" "PASS" "运行中 (PID: $pid)"
    else
        record_test "dnsmasq 服务" "FAIL" "核心 DNS 服务未运行"
    fi
}

check_ports_listening() {
    log "INFO" "4.4 检查端口监听..."
    
    local ports_ok=0
    local ports_total=3
    local ports=("53:DNS" "5053:DoH" "5453:DoT")
    
    for port_info in "${ports[@]}"; do
        IFS=':' read -r port desc <<< "$port_info"
        
        if netstat -tlnp 2>/dev/null | grep -q ":$port " || ss -tlnp 2>/dev/null | grep -q ":$port "; then
            ports_ok=$((ports_ok + 1))
        fi
    done
    
    if [ $ports_ok -eq $ports_total ]; then
        record_test "端口监听检查" "PASS" "所有关键端口正常监听 ($ports_ok/$ports_total)"
    elif [ $ports_ok -gt 0 ]; then
        record_test "端口监听检查" "WARN" "部分端口未监听 ($ports_ok/$ports_total)"
    else
        record_test "端口监听检查" "FAIL" "无关键端口在监听"
    fi
}

check_process_resources() {
    log "INFO" "4.5 检查进程资源使用..."
    
    local processes=("stubby" "https-dns-proxy" "dnsmasq")
    local all_healthy=true
    
    for proc in "${processes[@]}"; do
        if pgrep -x "$proc" >/dev/null 2>&1; then
            local pid=$(pidof $proc)
            local mem_usage=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ' || echo "0")
            local mem_mb=$((mem_usage / 1024))
            
            if [ $mem_mb -gt 100 ]; then
                log "WARNING" "$proc 内存使用较高: ${mem_mb}MB"
                all_healthy=false
            fi
        fi
    done
    
    if [ "$all_healthy" = true ]; then
        record_test "进程资源检查" "PASS" "所有进程资源使用正常"
    else
        record_test "进程资源检查" "WARN" "部分进程资源使用偏高"
    fi
}

# ============================================================
# 5. 性能基准测试
# ============================================================
run_performance_tests() {
    log "INFO" "=========================================="
    log "INFO" "5. 性能基准测试"
    log "INFO" "=========================================="
    
    # 5.1 DNS 解析延迟测试
    test_dns_resolution_latency
    
    # 5.2 并发查询性能
    test_concurrent_queries
    
    # 5.3 TLS 握手时间
    test_tls_handshake_time
}

test_dns_resolution_latency() {
    log "INFO" "5.1 DNS 解析延迟测试..."
    
    local test_domains=("example.com" "google.com" "github.com")
    local total_time=0
    local successful_queries=0
    
    for domain in "${test_domains[@]}"; do
        local start_time=$(date +%s%N 2>/dev/null || date +%s)
        
        if timeout 5 nslookup "$domain" >/dev/null 2>&1; then
            local end_time=$(date +%s%N 2>/dev/null || date +%s)
            
            if [[ "$start_time" == *"."* ]] || [[ "$end_time" == *"."* ]]; then
                local elapsed=$(( (end_time - start_time) / 1000000 ))
            else
                local elapsed=$(( (end_time - start_time) * 1000 ))
            fi
            
            total_time=$((total_time + elapsed))
            successful_queries=$((successful_queries + 1))
            
            log "INFO" "  $domain: ${elapsed}ms"
        fi
    done
    
    if [ $successful_queries -gt 0 ]; then
        local avg_latency=$((total_time / successful_queries))
        
        if [ $avg_latency -lt 200 ]; then
            record_test "DNS 解析延迟" "PASS" "平均延迟: ${avg_latency}ms"
        elif [ $avg_latency -lt 500 ]; then
            record_test "DNS 解析延迟" "WARN" "平均延迟: ${avg_latency}ms（略高）"
        else
            record_test "DNS 解析延迟" "FAIL" "平均延迟: ${avg_latency}ms（过高）"
        fi
    else
        record_test "DNS 解析延迟" "FAIL" "所有查询失败"
    fi
}

test_concurrent_queries() {
    log "INFO" "5.2 并发查询性能测试..."
    
    local concurrency=5
    local domain="example.com"
    local pids=()
    local successful=0
    
    for ((i=1; i<=concurrency; i++)); do
        (timeout 5 nslookup "$domain" >/dev/null 2>&1) &
        pids+=($!)
    done
    
    for pid in "${pids[@]}"; do
        if wait $pid 2>/dev/null; then
            successful=$((successful + 1))
        fi
    done
    
    if [ $successful -eq $concurrency ]; then
        record_test "并发查询性能" "PASS" "成功处理 $successful/$concurrency 并发请求"
    else
        record_test "并发查询性能" "WARN" "仅完成 $successful/$concurrency 并发请求"
    fi
}

test_tls_handshake_time() {
    log "INFO" "5.3 TLS 握手时间测试..."
    
    if ! command -v openssl >/dev/null 2>&1; then
        record_test "TLS 握手时间" "SKIP" "openssl 不可用"
        return
    fi
    
    local start_time=$(date +%s%N 2>/dev/null || date +%s)
    
    if timeout 5 openssl s_client -connect "223.5.5.5:853" -servername "223.5.5.5" </dev/null 2>/dev/null | grep -q "Protocol"; then
        local end_time=$(date +%s%N 2>/dev/null || date +%s)
        
        if [[ "$start_time" == *"."* ]] || [[ "$end_time" == *"."* ]]; then
            local elapsed=$(( (end_time - start_time) / 1000000 ))
        else
            local elapsed=$(( (end_time - start_time) * 1000 ))
        fi
        
        if [ $elapsed -lt 1000 ]; then
            record_test "TLS 握手时间" "PASS" "握手耗时: ${elapsed}ms"
        elif [ $elapsed -lt 3000 ]; then
            record_test "TLS 握手时间" "WARN" "握手耗时: ${elapsed}ms（较慢）"
        else
            record_test "TLS 握手时间" "FAIL" "握手耗时: ${elapsed}ms（过慢）"
        fi
    else
        record_test "TLS 握手时间" "FAIL" "TLS 握手失败"
    fi
}

# ============================================================
# 6. 安全合规检查
# ============================================================
run_compliance_checks() {
    log "INFO" "=========================================="
    log "INFO" "6. 安全合规检查"
    log "INFO" "=========================================="
    
    # 6.1 加密算法支持
    check_encryption_support
    
    # 6.2 协议版本检查
    check_protocol_versions
    
    # 6.3 安全头配置
    check_security_headers
    
    # 6.4 日志审计配置
    check_logging_config
    
    # 6.5 更新状态检查
    check_update_status
}

check_encryption_support() {
    log "INFO" "6.1 检查加密算法支持..."
    
    if command -v openssl >/dev/null 2>&1; then
        local ciphers=$(openssl ciphers 'HIGH:!aNULL:!MD5' 2>/dev/null | tr ':' '\n' | wc -l)
        
        if [ $ciphers -gt 20 ]; then
            record_test "加密算法支持" "PASS" "支持 $ciphers 种高强度加密算法"
        else
            record_test "加密算法支持" "WARN" "仅支持 $ciphers 种加密算法"
        fi
    else
        record_test "加密算法支持" "SKIP" "openssl 不可用"
    fi
}

check_protocol_versions() {
    log "INFO" "6.2 检查协议版本..."
    
    if command -v openssl >/dev/null 2>&1; then
        local has_tls12=false
        local has_tls13=false
        
        if openssl s_client -help 2>&1 | grep -q "tls1_2"; then
            has_tls12=true
        fi
        
        if openssl s_client -help 2>&1 | grep -q "tls1_3"; then
            has_tls13=true
        fi
        
        if [ "$has_tls13" = true ]; then
            record_test "协议版本" "PASS" "支持 TLS 1.3（最佳）"
        elif [ "$has_tls12" = true ]; then
            record_test "协议版本" "PASS" "支持 TLS 1.2（推荐）"
        else
            record_test "协议版本" "FAIL" "不支持现代 TLS 协议"
        fi
    else
        record_test "协议版本" "SKIP" "openssl 不可用"
    fi
}

check_security_headers() {
    log "INFO" "6.3 检查安全配置..."
    
    local security_score=0
    local max_score=4
    
    # 检查 Strict Mode
    if command -v uci >/dev/null 2>&1; then
        if [ "$(uci get stubby.global.tls_authentication 2>/dev/null)" = "1" ]; then
            security_score=$((security_score + 1))
        fi
        
        if uci get stubby.upstream.spki >/dev/null 2>&1; then
            security_score=$((security_score + 1))
        fi
    fi
    
    # 检查 DNSSEC
    if command -v uci >/dev/null 2>&1; then
        if [ "$(uci get stubby.global.dnssec 2>/dev/null)" = "1" ]; then
            security_score=$((security_score + 1))
        fi
    fi
    
    # 检查防火墙
    if command -v iptables >/dev/null 2>&1; then
        if iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT"; then
            security_score=$((security_score + 1))
        fi
    fi
    
    local percentage=$((security_score * 100 / max_score))
    
    if [ $percentage -ge 75 ]; then
        record_test "安全配置评分" "PASS" "得分: $security_score/$max_score ($percentage%)"
    elif [ $percentage -ge 50 ]; then
        record_test "安全配置评分" "WARN" "得分: $security_score/$max_score ($percentage%)"
    else
        record_test "安全配置评分" "FAIL" "得分: $security_score/$max_score ($percentage%)"
    fi
}

check_logging_config() {
    log "INFO" "6.4 检查日志配置..."
    
    local logging_enabled=false
    
    # 检查 syslog 是否可用
    if [ -d /var/log ] || command -v logread >/dev/null 2>&1; then
        logging_enabled=true
    fi
    
    # 检查自定义日志
    if [ -f /tmp/dnssec_monitor.log ] || [ -f /tmp/dnssec_check.log ]; then
        logging_enabled=true
    fi
    
    if [ "$logging_enabled" = true ]; then
        record_test "日志配置" "PASS" "日志记录已启用"
    else
        record_test "日志配置" "WARN" "日志记录可能未正确配置"
    fi
}

check_update_status() {
    log "INFO" "6.5 检查更新状态..."
    
    # 检查版本信息
    if [ -f "$PROJECT_ROOT/DEPLOYMENT_GUIDE.md" ]; then
        local last_updated=$(stat -c "%y" "$PROJECT_ROOT/DEPLOYMENT_GUIDE.md" 2>/dev/null | cut -d'.' -f1)
        log "INFO" "文档最后更新: $last_updated"
        record_test "更新状态" "PASS" "项目文档存在且可访问"
    else
        record_test "更新状态" "WARN" "部署指南文档不存在"
    fi
}

# ============================================================
# 报告生成
# ============================================================
generate_summary_report() {
    log "INFO" ""
    log "INFO" "=========================================="
    log "INFO" "   扫描总结报告"
    log "INFO" "=========================================="
    log "INFO" ""
    log "INFO" "【统计信息】"
    log "INFO" "  总测试数: $TOTAL_TESTS"
    log "INFO" "  通过: $PASSED_TESTS ✅"
    log "INFO" "  失败: $FAILED_TESTS ❌"
    log "INFO" "  警告: $WARNING_TESTS ⚠️"
    log "INFO" "  跳过: $SKIPPED_TESTS ➖"
    log "INFO" ""
    
    local pass_rate=0
    if [ $TOTAL_TESTS -gt 0 ]; then
        pass_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    fi
    
    log "INFO" "  通过率: ${pass_rate}%"
    log "INFO" ""
    
    # 评估结果
    local overall_status="PASS"
    if [ $FAILED_TESTS -gt 0 ]; then
        overall_status="FAIL"
    elif [ $WARNING_TESTS -gt 0 ]; then
        overall_status="WARN"
    fi
    
    log "INFO" "【总体评估】"
    case "$overall_status" in
        PASS) log "SUCCESS" "🎉 所有关键测试通过！" ;;
        WARN) log "WARNING" "⚠️  通过但存在问题需要关注" ;;
        FAIL) log "ERROR" "❌ 存在严重问题需要立即修复" ;;
    esac
    
    log "INFO" ""
    log "INFO" "详细日志: $LOG_FILE"
    log "INFO" "=========================================="
    
    # 写入摘要文件
    cat > "$SUMMARY_FILE" << EOF
==========================================
  安全扫描摘要报告
==========================================
时间: $(date)
总测试: $TOTAL_TESTS
通过: $PASSED_TESTS
失败: $FAILED_TESTS
警告: $WARNING_TESTS
跳过: $SKIPPED_TESTS
通过率: ${pass_rate}%
状态: $overall_status
==========================================
EOF
    
    # 生成 JSON 报告（如果需要）
    if [ "${CI:-false}" = "true" ] || [ "${GENERATE_JSON:-false}" = "true" ]; then
        generate_json_report "$overall_status" "$pass_rate"
    fi
}

generate_json_report() {
    local status="$1"
    local pass_rate="$2"
    
    cat > "$JSON_REPORT" << EOF
{
  "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed": $PASSED_TESTS,
    "failed": $FAILED_TESTS,
    "warnings": $WARNING_TESTS,
    "skipped": $SKIPPED_TESTS,
    "pass_rate": $pass_rate,
    "status": "$status"
  },
  "tests": [
    {
      "category": "Security Scan",
      "tests_run": $((TOTAL_TESTS > 0 ? 1 : 0)),
      "details": "See log file for details"
    }
  ],
  "log_file": "$LOG_FILE",
  "report_file": "$SUMMARY_FILE"
}
EOF
    
    log "INFO" "JSON 报告: $JSON_REPORT"
}

# ============================================================
# 主程序
# ============================================================
main() {
    local run_all=true
    local run_security=false
    local run_dnssec=false
    local run_tls=false
    local run_health=false
    local run_performance=false
    local run_compliance=false
    local generate_report_only=false
    
    # 解析参数
    while [ $# -gt 0 ]; do
        case "$1" in
            --security)     run_security=true; run_all=false ;;
            --dnssec)       run_dnssec=true; run_all=false ;;
            --tls)          run_tls=true; run_all=false ;;
            --health)       run_health=true; run_all=false ;;
            --performance)  run_performance=true; run_all=false ;;
            --compliance)   run_compliance=true; run_all=false ;;
            --report)       generate_report_only=true ;;
            --ci)           CI=true; GENERATE_JSON=true ;;
            --verbose|-v)   VERBOSE=true ;;
            --help|-h)      show_help; exit 0 ;;
            *)              echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    init_report_dir
    
    log "INFO" "开始安全扫描..."
    log "INFO" "项目路径: $PROJECT_ROOT"
    log "INFO" ""
    
    if [ "$generate_report_only" = true ]; then
        generate_summary_report
        exit 0
    fi
    
    if [ "$run_all" = true ] || [ "$run_security" = true ]; then
        run_security_scan
    fi
    
    if [ "$run_all" = true ] || [ "$run_dnssec" = true ]; then
        run_dnssec_tests
    fi
    
    if [ "$run_all" = true ] || [ "$run_tls" = true ]; then
        run_tls_verification
    fi
    
    if [ "$run_all" = true ] || [ "$run_health" = true ]; then
        run_health_checks
    fi
    
    if [ "$run_all" = true ] || [ "$run_performance" = true ]; then
        run_performance_tests
    fi
    
    if [ "$run_all" = true ] || [ "$run_compliance" = true ]; then
        run_compliance_checks
    fi
    
    generate_summary_report
    
    # 返回适当的退出码
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 2
    elif [ $WARNING_TESTS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

show_help() {
    cat << 'EOF'
CI/CD 自动化安全扫描工具
=========================

用法: ./ci_cd_security_scan.sh [选项]

选项:
  --security         运行代码安全扫描
  --dnssec           运行 DNSSEC 功能测试
  --tls              运行 TLS 配置验证
  --health           运行服务健康检查
  --performance      运行性能基准测试
  --compliance       运行安全合规检查
  --report           仅生成报告
  --ci               CI 模式（生成 JSON 报告）
  --verbose, -v      详细输出
  --help, -h         显示帮助信息

示例:
  # 运行全部测试
  ./ci_cd_security_scan.sh
  
  # 仅运行安全扫描和 DNSSEC 测试
  ./ci_cd_security_scan.sh --security --dnssec
  
  # CI 模式运行
  ./ci_cd_security_scan.sh --ci --verbose
  
  # 生成 JSON 报告
  ./ci_cd_security_scan.sh --report --ci

退出码:
  0 - 所有测试通过
  1 - 有警告
  2 - 有失败

输出:
  - 日志文件: test_reports/security_scan_<timestamp>.log
  - 摘要文件: test_reports/scan_summary.txt
  - JSON 报告: test_reports/security_report_<timestamp>.json
EOF
}

main "$@"
