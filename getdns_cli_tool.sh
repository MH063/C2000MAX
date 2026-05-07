#!/bin/sh

# ============================================================
# getdns CLI 完整工具链
# 功能：提供完整的 getdns 命令行接口
#       支持本地 DNSSEC 验证、链式验证、批量测试
# 使用方法: sh getdns_cli_tool.sh <命令> [参数]
# 示例:
#   sh getdns_cli_tool.sh query example.com
#   sh getdns_cli_tool.sh validate example.com --full
#   sh getdns_cli_tool.sh batch domains.txt
#   sh getdns_cli_tool.sh monitor example.com --interval 60
# ============================================================

COMMAND="$1"
shift

case "$COMMAND" in
    query|q)
        run_query "$@"
        ;;
    validate|v)
        run_validation "$@"
        ;;
    batch|b)
        run_batch_validation "$@"
        ;;
    monitor|m)
        run_monitor "$@"
        ;;
    trust-anchor|ta)
        manage_trust_anchor "$@"
        ;;
    dnskey)
        fetch_dnskey_records "$@"
        ;;
    rrsig)
        fetch_rrsig_records "$@"
        ;;
    ds)
        fetch_ds_records "$@"
        ;;
    status|s)
        show_status "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "未知命令: $COMMAND"
        echo "使用 '$0 help' 查看帮助信息"
        exit 1
        ;;
esac

run_query() {
    local domain="$1"
    shift
    
    local record_type="A"
    local upstream=""
    local dnssec=false
    local verbose=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --type|-t) record_type="$2"; shift ;;
            --upstream|-u) upstream="$2"; shift ;;
            --dnssec|-d) dnssec=true ;;
            --verbose|-v) verbose=true ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定域名"
        exit 1
    fi
    
    echo "=========================================="
    echo "   DNS 查询: $domain (类型: $record_type)"
    echo "=========================================="
    
    # 构建 getdns_query 命令
    local cmd="getdns_query"
    [ -n "$upstream" ] && cmd="$cmd --upstream $upstream"
    [ "$dnssec" = true ] && cmd="$cmd --dnssec_return_status"
    cmd="$cmd $domain"
    
    if command -v getdns_query >/dev/null 2>&1; then
        echo ""
        echo "执行命令: $cmd"
        echo ""
        eval $cmd
    else
        echo "getdns_query 不可用，使用 nslookup..."
        
        local ns_cmd="nslookup -type=$record_type $domain"
        [ -n "$upstream" ] && ns_cmd="$ns_cmd $upstream"
        
        eval $ns_cmd
    fi
}

run_validation() {
    local domain="$1"
    shift
    
    local full_chain=false
    local upstream=""
    local verbose=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --full|-f) full_chain=true ;;
            --upstream|-u) upstream="$2"; shift ;;
            --verbose|-v) verbose=true ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定域名"
        exit 1
    fi
    
    # 调用本地验证器
    local validator_cmd="sh $(dirname $0)/local_dnssec_validator.sh $domain"
    [ "$full_chain" = true ] && validator_cmd="$validator_cmd --full-chain"
    [ -n "$upstream" ] && validator_cmd="$validator_cmd --upstream $upstream"
    [ "$verbose" = true ] && validator_cmd="$validator_cmd --verbose"
    
    eval $validator_cmd
}

run_batch_validation() {
    local domain_file="$1"
    shift
    
    local upstream=""
    local output_file="/tmp/dnssec_batch_results.csv"
    local parallel=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --output|-o) output_file="$2"; shift ;;
            --upstream|-u) upstream="$2"; shift ;;
            --parallel|-p) parallel=true ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ ! -f "$domain_file" ]; then
        echo "错误: 域名列表文件不存在: $domain_file"
        exit 1
    fi
    
    echo "=========================================="
    echo "   批量 DNSSEC 验证"
    echo "=========================================="
    echo "域名字典: $domain_file"
    echo "输出文件: $output_file"
    echo ""
    
    # 创建 CSV 头
    echo "domain,timestamp,status,dnssec_valid,response_time_ms" > "$output_file"
    
    local total=0
    local success=0
    local failed=0
    
    while IFS= read -r domain || [ -n "$domain" ]; do
        # 跳过空行和注释
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        
        total=$((total + 1))
        
        echo -n "[$total] 验证 $domain ... "
        
        local start_time=$(date +%s%N 2>/dev/null || date +%s)
        
        # 执行验证
        local result="UNKNOWN"
        local cmd="sh $(dirname $0)/local_dnssec_validator.sh $domain"
        [ -n "$upstream" ] && cmd="$cmd --upstream $upstream"
        
        local output=$(eval $cmd 2>/dev/null | grep -E "(SECURE|INSECURE|BOGUS|UNKNOWN)" | tail -1)
        
        local end_time=$(date +%s%N 2>/dev/null || date +%s)
        
        # 计算响应时间
        local response_time=0
        if [[ "$start_time" == *"."* ]] || [[ "$end_time" == *"."* ]]; then
            response_time=$(( (end_time - start_time) / 1000000 ))
        else
            response_time=$(( (end_time - start_time) * 1000 ))
        fi
        
        # 解析结果
        if echo "$output" | grep -q "SECURE"; then
            result="SECURE"
            success=$((success + 1))
            echo "✅ 安全"
        elif echo "$output" | grep -q "INSECURE"; then
            result="INSECURE"
            success=$((success + 1))
            echo "⚠️  未签名"
        elif echo "$output" | grep -q "BOGUS"; then
            result="BOGUS"
            failed=$((failed + 1))
            echo "❌ 验证失败"
        else
            result="UNKNOWN"
            failed=$((failed + 1))
            echo "❓ 未知"
        fi
        
        # 写入 CSV
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        local dnssec_valid="false"
        [ "$result" = "SECURE" ] && dnssec_valid="true"
        
        echo "$domain,$timestamp,$result,$dnssec_valid,$response_time" >> "$output_file"
        
    done < "$domain_file"
    
    echo ""
    echo "=========================================="
    echo "   批量验证完成"
    echo "=========================================="
    echo "总计: $total 个域名"
    echo "成功: $success"
    echo "失败: $failed"
    echo "成功率: $((success * 100 / total))%"
    echo ""
    echo "详细结果已保存到: $output_file"
}

run_monitor() {
    local domain="$1"
    shift
    
    local interval=300
    local count=0
    local infinite=false
    local log_file="/tmp/dnssec_monitor.log"
    local alert_file="/tmp/dnssec_alerts.log"
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --interval|-i) interval="$2"; shift ;;
            --count|-c) count="$2"; shift ;;
            --infinite|-n) infinite=true ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定要监控的域名"
        exit 1
    fi
    
    echo "=========================================="
    echo "   DNSSEC 状态监控"
    echo "=========================================="
    echo "目标域名: $domain"
    echo "检查间隔: ${interval} 秒"
    [ "$count" -gt 0 ] && echo "检查次数: $count"
    [ "$infinite" = true ] && echo "模式: 无限循环（Ctrl+C 停止）"
    echo "日志文件: $log_file"
    echo "警报文件: $alert_file"
    echo ""
    
    local iteration=0
    
    while true; do
        iteration=$((iteration + 1))
        
        if [ "$count" -gt 0 ] && [ "$iteration" -gt "$count" ]; then
            break
        fi
        
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] 第 $iteration 次检查..."
        
        # 执行验证
        local cmd="sh $(dirname $0)/local_dnssec_validator.sh $domain"
        local output=$(eval $cmd 2>/dev/null)
        
        local result="UNKNOWN"
        if echo "$output" | grep -q "SECURE"; then
            result="SECURE"
        elif echo "$output" | grep -q "BOGUS"; then
            result="BOGUS"
            
            # 记录警报
            echo "[$timestamp] ALERT: DNSSEC validation FAILED for $domain" >> "$alert_file"
            echo "⚠️  [警报] DNSSEC 验证失败！"
        fi
        
        # 记录日志
        echo "[$timestamp] $domain: $result" >> "$log_file"
        
        echo "状态: $result"
        echo ""
        
        sleep $interval
    done
    
    echo "监控完成。"
}

manage_trust_anchor() {
    local action="$1"
    
    case "$action" in
        show|list)
            show_trust_anchors
            ;;
        update)
            update_trust_anchor
            ;;
        verify)
            verify_trust_anchor_local
            ;;
        *)
            echo "用法: $0 trust-anchor <show|update|verify>"
            exit 1
            ;;
    esac
}

show_trust_anchors() {
    local anchor_file="/usr/share/dns/root.key"
    
    echo "=========================================="
    echo "   DNSSEC 信任锚点"
    echo "=========================================="
    
    if [ -f "$anchor_file" ]; then
        echo "信任锚点文件: $anchor_file"
        echo ""
        cat "$anchor_file"
    else
        echo "信任锚点文件不存在"
        echo ""
        echo "使用内置根密钥："
        echo "根区域 DNSKEY (SHA-256):"
        echo "  E06D44B80B8F1D39A95C0B0D7C65DFFB41065D0B58B405050A563FA83755341A"
    fi
}

update_trust_anchor() {
    echo "更新信任锚点需要 root 权限"
    echo "请手动运行:"
    echo "  wget -O /usr/share/dns/root.key https://data.iana.org/root-anchors/root-anchors.xml"
    echo "  unbound-anchor -a /usr/share/dns/root.key"
}

verify_trust_anchor_local() {
    sh $(dirname $0)/local_dnssec_validator.sh dummy.example.com --check-trust-anchor
}

fetch_dnskey_records() {
    local domain="$1"
    shift
    
    local upstream=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --upstream|-u) upstream="$2"; shift ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定域名"
        exit 1
    fi
    
    echo "获取 $domain 的 DNSKEY 记录..."
    echo ""
    
    local cmd="nslookup -type=DNSKEY $domain"
    [ -n "$upstream" ] && cmd="$cmd $upstream"
    
    eval $cmd
}

fetch_rrsig_records() {
    local domain="$1"
    shift
    
    local upstream=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --upstream|-u) upstream="$2"; shift ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定域名"
        exit 1
    fi
    
    echo "获取 $domain 的 RRSIG 记录..."
    echo ""
    
    local cmd="nslookup -type=RRSIG $domain"
    [ -n "$upstream" ] && cmd="$cmd $upstream"
    
    eval $cmd
}

fetch_ds_records() {
    local domain="$1"
    shift
    
    local upstream=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --upstream|-u) upstream="$2"; shift ;;
            *) echo "未知选项: $1"; exit 1 ;;
        esac
        shift
    done
    
    if [ -z "$domain" ]; then
        echo "错误: 请指定域名"
        exit 1
    fi
    
    echo "获取 $domain 的 DS 记录..."
    echo ""
    
    local cmd="nslookup -type=DS $domain"
    [ -n "$upstream" ] && cmd="$cmd $upstream"
    
    eval $cmd
}

show_status() {
    echo "=========================================="
    echo "   getdns 工具链状态"
    echo "=========================================="
    echo ""
    
    echo "【组件状态】"
    
    # 检查 getdns 库
    if [ -f /usr/lib/libgetdns.so.10 ] || [ -f /usr/lib/libgetdns.so.11 ]; then
        echo "✅ getdns 库: 已安装"
    else
        echo "❌ getdns 库: 未安装"
    fi
    
    # 检查 getdns_query 命令
    if command -v getdns_query >/dev/null 2>&1; then
        echo "✅ getdns_query: 可用 ($(getdns_query --version 2>/dev/null | head -1))"
    else
        echo "⚠️  getdns_query: 不可用（将使用备用方法）"
    fi
    
    # 检查 stubby
    if pgrep -x stubby >/dev/null 2>&1; then
        echo "✅ stubby 服务: 运行中 (PID: $(pidof stubby))"
    else
        echo "⚠️  stubby 服务: 未运行"
    fi
    
    # 检查 https-dns-proxy
    if pgrep -f https-dns-proxy >/dev/null 2>&1; then
        echo "✅ https-dns-proxy: 运行中 (PID: $(pgrep -f https-dns-proxy))"
    else
        echo "⚠️  https-dns-proxy: 未运行"
    fi
    
    echo ""
    echo "【信任锚点】"
    if [ -f /usr/share/dns/root.key ]; then
        echo "✅ 根密钥文件: 存在"
    else
        echo "⚠️  根密钥文件: 不存在（将使用内置锚点）"
    fi
    
    echo ""
    echo "【网络连接】"
    test_servers=("1.1.1.1:Cloudflare" "9.9.9.9:Quad9" "8.8.8.8:Google")
    for server_info in "${test_servers[@]}"; do
        IFS=':' read -r ip name <<< "$server_info"
        if timeout 2 nc -zv -w 2 $ip 53 >/dev/null 2>&1; then
            echo "✅ $name ($ip): 可达"
        else
            echo "❌ $name ($ip): 不可达"
        fi
    done
    
    echo ""
    echo "=========================================="
}

show_help() {
    cat << 'EOF'
getdns CLI 完整工具链
=====================

用法: getdns_cli_tool.sh <命令> [参数]

命令:
  query, q         执行 DNS 查询
  validate, v      验证 DNSSEC 状态
  batch, b         批量验证多个域名
  monitor, m       监控 DNSSEC 状态
  trust-anchor, ta 管理信任锚点
  dnskey           获取 DNSKEY 记录
  rrsig            获取 RRSIG 记录
  ds               获取 DS 记录
  status, s        显示系统状态
  help             显示此帮助信息

示例:
  # 查询域名
  getdns_cli_tool.sh query example.com
  
  # 启用 DNSSEC 验证查询
  getdns_cli_tool.sh query example.com --dnssec --verbose
  
  # 完整验证
  getdns_cli_tool.sh validate example.com --full --verbose
  
  # 批量验证
  getdns_cli_tool.sh batch domains.txt --output results.csv
  
  # 持续监控
  getdns_cli_tool.sh monitor example.com --interval 60 --infinite
  
  # 获取 DNSKEY 记录
  getdns_cli_tool.sh dnskey example.com --upstream 1.1.1.1
  
  # 显示系统状态
  getdns_cli_tool.sh status

更多信息请参考文档:
  - DNSSEC_使用说明.md
  - local_dnssec_validator.sh --help
EOF
}
