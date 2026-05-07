#!/bin/sh

# ============================================================
# DNSSEC 状态监控脚本
# 功能：持续监控 DNSSEC 验证状态，检测异常
# 使用方法: sh monitor_dnssec.sh [选项]
# 示例:
#   sh monitor_dnssec.sh                    # 单次检查
#   sh monitor_dnssec.sh --daemon           # 后台守护进程
#   sh monitor_dnssec.sh --interval 60      # 每 60 秒检查一次
#   sh monitor_dnssec.sh --stop             # 停止监控
# ============================================================

DAEMON_MODE=false
INTERVAL=300
STOP_MONITOR=false
LOG_FILE="/tmp/dnssec_monitor.log"
PID_FILE="/tmp/dnssec_monitor.pid"
ALERT_LOG="/tmp/dnssec_alerts.log"
TEST_DOMAIN="example.com"

while [ $# -gt 0 ]; do
    case "$1" in
        --daemon|-d)
            DAEMON_MODE=true
            ;;
        --interval|-i)
            INTERVAL="$2"
            shift
            ;;
        --stop|-s)
            STOP_MONITOR=true
            ;;
        --domain)
            TEST_DOMAIN="$2"
            shift
            ;;
        -h|--help)
            echo "DNSSEC 状态监控工具"
            echo ""
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --daemon, -d          后台守护进程模式"
            echo "  --interval, -n <秒>   检查间隔（默认 300 秒）"
            echo "  --stop, -s            停止监控"
            echo "  --domain <域名>       测试域名（默认 example.com）"
            echo "  --help, -h            显示帮助信息"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
    shift
done

log() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO|WARNING)
            echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
            if [ "$DAEMON_MODE" != "true" ]; then
                echo "[$level] $msg"
            fi
            ;;
        ERROR|ALERT)
            echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
            echo "[$timestamp] [$level] $msg" >> "$ALERT_LOG"
            if [ "$DAEMON_MODE" != "true" ]; then
                echo "[$level] $msg" >&2
            fi
            ;;
        DEBUG)
            echo "[$timestamp] [DEBUG] $msg" >> "$LOG_FILE"
            ;;
    esac
}

stop_monitor() {
    log "INFO" "正在停止 DNSSEC 监控..."
    
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 $pid 2>/dev/null; then
            kill $pid 2>/dev/null
            sleep 1
            
            if kill -0 $pid 2>/dev/null; then
                kill -9 $pid 2>/dev/null
            fi
            
            rm -f "$PID_FILE"
            log "INFO" "✅ 监控已停止 (PID: $pid)"
        else
            log "WARNING" "监控进程不存在（PID 文件已清理）"
            rm -f "$PID_FILE"
        fi
    else
        log "INFO" "没有找到运行中的监控进程"
    fi
    
    exit 0
}

check_dns_service_status() {
    local status_ok=true
    
    if ! pgrep -x stubby >/dev/null 2>&1; then
        log "WARNING" "stubby 服务未运行"
        status_ok=false
    fi
    
    if ! pgrep -f https-dns-proxy >/dev/null 2>&1; then
        log "WARNING" "https-dns-proxy 服务未运行"
        status_ok=false
    fi
    
    return $([ "$status_ok" = "true" ] && echo 0 || echo 1)
}

perform_dnssec_check() {
    local check_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    log "DEBUG" "--- 开始 DNSSEC 检查 ($check_time) ---"
    
    local test_result="UNKNOWN"
    local response_time=-1
    
    local start_time=$(date +%s%N 2>/dev/null || date +%s)
    
    if timeout 5 nslookup $TEST_DOMAIN >/dev/null 2>&1; then
        test_result="OK"
        
        local end_time=$(date +%s%N 2>/dev/null || date +%s)
        if [ -n "$start_time" ] && [ -n "$end_time" ]; then
            if [[ "$start_time" == *"."* ]] || [[ "$end_time" == *"."* ]]; then
                response_time=$(( (end_time - start_time) / 1000000 ))
            else
                response_time=$(( (end_time - start_time) * 1000 ))
            fi
        fi
    else
        test_result="FAIL"
        log "ERROR" "DNS 查询失败: $TEST_DOMAIN"
    fi
    
    log "DEBUG" "DNSSEC 检查结果: $test_result (响应时间: ${response_time}ms)"
    
    echo "$check_time|$test_result|$response_time"
}

analyze_results() {
    local result_line="$1"
    
    IFS='|' read -r check_time test_result response_time <<< "$result_line"
    
    case "$test_result" in
        OK)
            if [ "$response_time" -gt 5000 ] 2>/dev/null; then
                log "WARNING" "DNS 响应时间过长: ${response_time}ms (阈值: 5000ms)"
            elif [ "$response_time" -lt 0 ] 2>/dev/null; then
                : # 无法测量时间
            else
                log "DEBUG" "✅ DNS 正常 (响应时间: ${response_time}ms)"
            fi
            ;;
        FAIL)
            log "ERROR" "❌ DNSSEC 验证失败！可能存在安全问题！"
            log "ERROR" "   时间: $check_time"
            log "ERROR" "   域名: $TEST_DOMAIN"
            
            check_dns_service_status || true
            ;;
        *)
            log "WARNING" "未知状态: $test_result"
            ;;
    esac
}

monitor_loop() {
    log "INFO" "=========================================="
    log "INFO" "   DNSSEC 状态监控已启动"
    log "INFO" "=========================================="
    log "INFO" "测试域名: $TEST_DOMAIN"
    log "INFO" "检查间隔: ${INTERVAL} 秒"
    log "INFO" "日志文件: $LOG_FILE"
    log "INFO" "警报文件: $ALERT_LOG"
    log "INFO" "PID 文件: $PID_FILE"
    log "INFO" "=========================================="
    
    while true; do
        local result=$(perform_dnssec_check)
        analyze_results "$result"
        
        sleep $INTERVAL
    done
}

cleanup() {
    log "INFO" "收到终止信号，正在清理..."
    rm -f "$PID_FILE"
    exit 0
}

main() {
    if [ "$STOP_MONITOR" = "true" ]; then
        stop_monitor
    fi
    
    if [ "$DAEMON_MODE" = "true" ]; then
        if [ -f "$PID_FILE" ]; then
            local existing_pid=$(cat "$PID_FILE")
            if kill -0 $existing_pid 2>/dev/null; then
                log "ERROR" "监控进程已在运行 (PID: $existing_pid)"
                log "INFO" "使用 --stop 选项停止现有进程"
                exit 1
            fi
            rm -f "$PID_FILE"
        fi
        
        nohup $0 --interval $INTERVAL --domain $TEST_DOMAIN </dev/null >>/dev/null 2>&1 &
        local new_pid=$!
        echo $new_pid > "$PID_FILE"
        
        log "INFO" "✅ 守护进程已启动 (PID: $new_pid)"
        log "INFO" "使用 '$0 --stop' 停止监控"
        exit 0
    fi
    
    trap cleanup SIGTERM SIGINT
    
    if [ ! "$DAEMON_MODE" = "true" ]; then
        echo "=========================================="
        echo "   DNSSEC 状态检查"
        echo "=========================================="
        echo ""
        
        check_dns_service_status
        
        echo ""
        local result=$(perform_dnssec_check)
        analyze_results "$result"
        
        echo ""
        echo "=========================================="
        echo "   检查完成"
        echo "=========================================="
        echo ""
        echo "提示:"
        echo "  - 使用 --daemon 启动后台监控"
        echo "  - 使用 --stop 停止监控"
        echo "  - 日志位置: $LOG_FILE"
        echo "  - 警报位置: $ALERT_LOG"
    else
        monitor_loop
    fi
}

main
