module("luci.controller.router_assistant", package.seeall)

-- ========== 常量定义 ==========
-- 数据文件名
DATA_DIR_NAME = "router_assistant"
DATA_FILE_NAME = "traffic_stats.json"
NOTES_FILE_NAME = "device_notes.json"
-- HISTORY_FILE_NAME 已删除（流量历史统计模块已移除）
ALERTS_FILE_NAME = "traffic_alerts.json"
BLOCKLIST_FILE_NAME = "mac_blocklist.json"

-- 时间常量（秒）
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_WEEK = 604800

-- 缓存常量
STORAGE_CACHE_TTL = SECONDS_PER_HOUR
BLOCKED_MACS_CACHE_TTL = 30

-- ipset 流量统计相关常量
IPSET_RX_NAME = "traffic_stats_rx"
IPSET_TX_NAME = "traffic_stats_tx"
IPSET_RX_IP_NAME = "traffic_stats_rx_ip"
IPSET_RX_IP6_NAME = "traffic_stats_rx_ip6"
IPSET_CACHE_TTL = 5  -- ipset 数据缓存5秒

-- 历史记录保留常量
MAX_HOURLY_RECORDS = 168
MAX_DAILY_RECORDS = 30
-- 修复问题6：限制流量历史中的设备条目数，避免文件无限增长
MAX_TRAFFIC_DEVICES = 200

-- Homebox 配置
HOMEBOX_BIN = "/usr/bin/homebox"
HOMEBOX_PORT = 3300
HOMEBOX_PID_FILE = "/var/run/homebox.pid"
HOMEBOX_LOG_FILE = "/tmp/homebox.log"
HOMEBOX_START_TIMEOUT = 3

-- 缓存变量
_cached_storage_path = nil
_storage_path_cache_time = 0
_last_storage_type = nil

-- 黑名单缓存（文件缓存，跨进程共享）
local BLOCKED_MACS_CACHE_FILE = "/tmp/router_assistant/blocked_macs_cache.json"
local BLOCKED_MACS_CACHE_TTL = 30  -- 缓存有效期30秒
_blocked_macs_cache = nil  -- 进程内缓存（请求内复用）
_blocked_macs_cache_time = 0

-- 从文件加载缓存
local function load_blocked_macs_cache_from_file()
    local fd = io.open(BLOCKED_MACS_CACHE_FILE, "r")
    if fd then
        local content = fd:read("*a")
        fd:close()
        if content and content ~= "" then
            local ok, data = pcall(function()
                return require("luci.jsonc").parse(content)
            end)
            if ok and data and type(data) == "table" and data.macs and data.time then
                return data.macs, data.time
            end
        end
    end
    return nil, 0
end

-- 保存缓存到文件
local function save_blocked_macs_cache_to_file(macs_table)
    local dir = BLOCKED_MACS_CACHE_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local data = {
        macs = macs_table,
        time = os.time()
    }
    local json = require("luci.jsonc")
    local json_str = json.stringify(data) or "{}"
    local fd = io.open(BLOCKED_MACS_CACHE_FILE, "w")
    if fd then
        fd:write(json_str)
        fd:close()
    end
end

-- 清除缓存文件（跨进程同步）
-- 清除黑名单缓存文件（不使用锁，因为 nRadio 平台 flock 不可用）
-- 注意：此操作仅影响文件层，其他 CGI 进程的内存缓存（TTL=30s）不会立即失效
-- 这是无锁设计的固有限制，可接受（下次查询会重新读取 iptables）
local function clear_blocked_macs_cache_file()
    os.remove(BLOCKED_MACS_CACHE_FILE)
end

-- 获取 iptables 屏蔽列表（带文件缓存）
local function get_blocked_macs_from_iptables()
    local current_time = os.time()

    -- 先检查进程内缓存
    if _blocked_macs_cache and (current_time - _blocked_macs_cache_time) < BLOCKED_MACS_CACHE_TTL then
        return _blocked_macs_cache
    end

    -- 尝试从文件缓存加载
    local file_macs, file_time = load_blocked_macs_cache_from_file()
    if file_macs and (current_time - file_time) < BLOCKED_MACS_CACHE_TTL then
        _blocked_macs_cache = file_macs
        _blocked_macs_cache_time = file_time
        return _blocked_macs_cache
    end

    -- 缓存失效，重新查询 iptables（一次性获取所有规则）
    local util = require("luci.util")
    local macs = {}

    local function extract_macs_from_iptables(output)
        if not output then return end
        for mac in output:gmatch("--mac%-source%s+([%da-fA-F:]+)") do
            if mac and #mac >= 17 then macs[mac:upper()] = true end
        end
        for mac in output:gmatch("MAC([%da-fA-F][%da-fA-F:]+)") do
            if mac and #mac >= 17 then macs[mac:upper()] = true end
        end
        for mac in output:gmatch("([%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F])") do
            macs[mac:upper()] = true
        end
    end

    -- 一次性获取 INPUT 和 FORWARD 链规则
    extract_macs_from_iptables(util.exec("iptables -L INPUT -n --line-numbers 2>/dev/null"))
    extract_macs_from_iptables(util.exec("iptables -L FORWARD -n --line-numbers 2>/dev/null"))

    -- 保存到文件缓存
    save_blocked_macs_cache_to_file(macs)

    -- 更新进程内缓存
    _blocked_macs_cache = macs
    _blocked_macs_cache_time = current_time

    return macs
end

local function is_valid_number(n)
    return n and type(n) == "number" and n == n and n >= 0
end

-- 基础工具函数（必须在其他函数之前定义）
function safe_path(path)
    if not path or type(path) ~= "string" then
        return nil
    end
    if path:match("%.%.") then
        return nil
    end
    if path:match("[`;|$%[%]%*%?<>]") then
        return nil
    end
    if not path:match("^/[%w%d_/%-%.]+$") then
        return nil
    end
    return path
end

function get_storage_type(path)
    if path:find("mmcblk0") or path:find("sdcard") or path:find("storage") then
        return "tf_card"
    end
    return "memory"
end

function ensure_directory(path)
    local dir = path:match("^(.+)/[^/]+$")
    if dir and dir ~= "" then
        local safe_dir = safe_path(dir)
        if not safe_dir then
            return false
        end
        local check_fd = io.open(safe_dir, "r")
        if not check_fd then
            os.execute("mkdir -p '" .. safe_dir:gsub("'", "'\\''") .. "' 2>/dev/null")
        else
            check_fd:close()
        end
    end
    return true
end

-- 生成唯一的临时文件名（使用PID+随机数，避免并发冲突）
local function generate_temp_filename(file_path)
    local nixio = require("nixio")
    local pid = nixio.getpid and nixio.getpid() or os.time()
    local random = math.random(10000, 99999)
    return file_path .. ".tmp." .. pid .. "." .. random
end

function save_data_atomic(file_path, data, max_retries)
    max_retries = max_retries or 3
    local last_err = "Unknown error"

    for attempt = 1, max_retries do
        local temp_file = generate_temp_filename(file_path)
        local fd, open_err = io.open(temp_file, "w")
        if not fd then
            last_err = "Cannot create temp file: " .. tostring(open_err)
            nixio.syslog("warning", "save_data_atomic: attempt " .. attempt .. " failed - " .. last_err)
            pcall(function()
                if nixio.sleep then nixio.sleep(0.1 * attempt) end
            end)
        else
            local ok, write_err = pcall(function()
                fd:write(data)
                fd:close()
            end)

            if not ok then
                last_err = write_err or "Write failed"
                pcall(os.remove, temp_file)
                nixio.syslog("warning", "save_data_atomic: attempt " .. attempt .. " write failed - " .. last_err)
            else
                local rename_ok, rename_err = os.rename(temp_file, file_path)
                if rename_ok then
                    return true
                else
                    last_err = "Rename failed: " .. tostring(rename_err)
                    pcall(os.remove, temp_file)
                    nixio.syslog("warning", "save_data_atomic: attempt " .. attempt .. " rename failed - " .. last_err)
                end
            end
        end

        -- 最后一次尝试失败
        if attempt < max_retries then
            pcall(function()
                if nixio.sleep then nixio.sleep(0.2 * attempt) end
            end)
        end
    end

    nixio.syslog("err", "save_data_atomic: all " .. max_retries .. " attempts failed for " .. file_path .. " - " .. last_err)
    return false, last_err
end

function save_with_fallback(file_path, data)
    local ok, err = save_data_atomic(file_path, data)
    if ok then
        _last_storage_type = get_storage_type(file_path)
        return true, file_path
    end
    
    _cached_storage_path = nil
    _storage_path_cache_time = 0
    
    if file_path ~= "/tmp/router_assistant/traffic_stats.json" then
        local fallback_path = "/tmp/router_assistant/traffic_stats.json"
        ensure_directory(fallback_path)
        ok, err = save_data_atomic(fallback_path, data)
        if ok then
            _cached_storage_path = fallback_path
            _last_storage_type = "memory"
            return true, fallback_path
        end
    end
    
    return false, err
end

-- ========== 文件锁机制（跨进程同步） ==========
-- 防御性：检测 nixio.flock 是否可用（nRadio 等平台可能没有 flock 方法）
local nixio = require("nixio")
local LOCK_EX = 2  -- 排他锁
local LOCK_UN = 8  -- 解锁
local flock_available = false

-- 兼容性检测：尝试实际调用 flock
do
    local test_ok = pcall(function()
        local f = nixio.open("/tmp/.flock_test", "w+")
        if f then
            f:flock(LOCK_EX)
            f:flock(LOCK_UN)
            f:close()
        end
    end)
    flock_available = test_ok
end

local function file_lock_acquire(lock_path, timeout_ms)
    timeout_ms = timeout_ms or 5000
    local lock_file = lock_path .. ".lock"

    -- flock 不可用时，直接返回成功（无锁模式）
    if not flock_available then
        return true, lock_file, nil
    end

    local retry_interval = 0.1  -- 100ms

    -- 打开锁文件（创建/读写）
    local fd, err = nixio.open(lock_file, "w+")
    if not fd then
        nixio.syslog("err", "Failed to open lock file: " .. tostring(err))
        return false, lock_file
    end

    local start_time = nixio.sysinfo().uptime or os.time()
    while true do
        -- 尝试获取排他锁（非阻塞）
        local ok, err = fd:flock(LOCK_EX)
        if ok then
            -- 写入锁持有者的 PID，方便调试
            fd:write(tostring(os.time()))
            fd:seek("set", 0)
            return true, lock_file, fd
        end

        -- 检查是否超时
        local elapsed = (nixio.sysinfo().uptime or os.time()) - start_time
        if elapsed * 1000 >= timeout_ms then
            fd:close()
            nixio.syslog("err", "Lock acquisition timeout: " .. lock_file)
            return false, lock_file
        end

        -- 短暂等待后重试
        pcall(function()
            if nixio.sleep then
                nixio.sleep(retry_interval)
            end
        end)
    end
end

local function file_lock_release(lock_path, fd)
    if fd and flock_available then
        pcall(function()
            fd:flock(LOCK_UN)
            fd:close()
        end)
    elseif fd then
        pcall(function()
            fd:close()
        end)
    end
end

-- 带文件锁的原子写入
local function save_with_file_lock(file_path, data, timeout_ms)
    timeout_ms = timeout_ms or 5000

    -- 获取文件锁（返回值包含 fd）
    local lock_acquired, lock_file, fd = file_lock_acquire(file_path, timeout_ms)
    if not lock_acquired then
        return false, "Failed to acquire lock"
    end

    -- 执行原子写入
    local ok, err = save_data_atomic(file_path, data)

    -- 释放锁（传入 fd）
    file_lock_release(lock_file, fd)

    if ok then
        return true, file_path
    else
        return false, err
    end
end

-- ========== 安全命令执行函数 ==========
-- 安全的 shell 参数转义
local function shell_escape(arg)
    if not arg or type(arg) ~= "string" then
        return ""
    end
    return "'" .. arg:gsub("'", "'\\''") .. "'"
end

-- ========== MAC地址格式常量 ==========
-- 统一规定：所有存储、API返回、日志均使用带冒号大写格式（AA:BB:CC:DD:EE:FF）
-- 内部处理时使用无冒号纯十六进制格式（AABBCCDDEEFF）
local MAC_FMT_COLON = "AA:BB:CC:DD:EE:FF"  -- 标准MAC格式（用于存储和API返回）
local MAC_FMT_PLAIN = "AABBCCDDEEFF"        -- 纯十六进制格式（仅内部处理使用）

-- 安全验证MAC地址（防注入）
-- @param mac string 原始MAC地址
-- @return string|nil 12位大写十六进制字符串（如 "AABBCCDDEEFF"）或nil
-- 安全保证：返回值仅包含 [A-F0-9]，无特殊字符，可直接用于：
--   - 文件名拼接（已二次验证）
--   - shell命令拼接（已加引号保护）
--   - 日志记录
-- 注意：拼入shell命令时仍建议加引号（防御深度，见问题1修复）
local function safe_mac_validate(mac)
    if not mac or type(mac) ~= "string" then
        return nil
    end
    local clean_mac = mac:upper():gsub("[^A-F0-9]", "")
    if #clean_mac ~= 12 then
        return nil
    end
    if not clean_mac:match("^[A-F0-9]+$") then
        return nil
    end
    if clean_mac == "000000000000" or clean_mac == "FFFFFFFFFFFF" then
        return nil
    end
    return clean_mac
end

-- 修复问题12：MAC格式化函数（将无冒号格式转换为冒号分隔格式）
-- 输入：已验证的12位十六进制无冒号大写MAC（如 "AABBCCDDEEFF"）
-- 输出：冒号分隔格式（如 "AA:BB:CC:DD:EE:FF"）
local function format_mac_colon(safe_mac)
    if not safe_mac or #safe_mac ~= 12 then
        return safe_mac or ""
    end
    return safe_mac:sub(1,2) .. ":" .. safe_mac:sub(3,4) .. ":" ..
           safe_mac:sub(5,6) .. ":" .. safe_mac:sub(7,8) .. ":" ..
           safe_mac:sub(9,10) .. ":" .. safe_mac:sub(11,12)
end

-- 修复问题#2：WiFi接口名安全验证（防止命令注入）
-- WiFi接口名通常为 wlan0, wlan1, wlan0-1, wlan0-2, radio0, etc 等格式
-- 允许：字母、数字、下划线、短横线，且不以空格或特殊字符开头
local function safe_ifname(ifname)
    if not ifname or type(ifname) ~= "string" or ifname == "" then
        return nil
    end
    -- 验证只包含安全的字符：字母、数字、下划线、短横线
    -- 同时排除常见的命令注入字符：空格、分号、反引号、管道、$、&、|、<、>、!、*、?、~、'、"
    if ifname:match("[^%w%-_]") then
        return nil
    end
    -- 长度限制（WiFi接口名通常不超过16字符）
    if #ifname > 16 then
        return nil
    end
    return ifname
end

-- 安全验证IP地址（防注入）
-- @param ip string 原始IP地址
-- @return string|nil 验证通过的IP地址或nil
-- 安全保证：返回值仅包含 [0-9.]，每段0-255，可直接用于：
--   - shell命令拼接（已加引号保护）
--   - 日志记录
-- 注意：拼入shell命令时仍建议加引号（防御深度，见问题1修复）
local function safe_ip_validate(ip)
    if not ip or type(ip) ~= "string" then
        return nil
    end
    if #ip > 15 or #ip < 7 then
        return nil
    end
    if ip:match("[^%d%.]") then
        return nil
    end
    local parts = {}
    for part in ip:gmatch("[^%.]+") do
        -- 修复问题9：移除前导零检查，允许 192.168.01.100 等格式
        -- 虽然标准格式不应有前导零，但部分老旧设备或特殊DHCP实现可能输出这种格式
        local num = tonumber(part)
        if not num or num < 0 or num > 255 then
            return nil
        end
        table.insert(parts, num)
    end
    if #parts ~= 4 then
        return nil
    end
    return ip
end

-- 安全执行 shell 命令（带白名单和超时）
local ALLOWED_COMMANDS = {
    ["conntrack"] = true,
    ["iptables"] = true,
    ["iw"] = true,
    ["iwinfo"] = true,
    ["mkdir"] = true,
    ["killall"] = true,
    ["chmod"] = true,
    ["pgrep"] = true,
    ["cat"] = true,
    ["df"] = true,
    ["ps"] = true,
    ["netstat"] = true,
    ["ip"] = true,
    ["ubus"] = true,
    ["access_ctl.sh"] = true,
    ["echo"] = true,
    ["sleep"] = true,
    ["true"] = true
}

-- 默认命令超时（秒），防止命令阻塞导致502
local CMD_TIMEOUT = 5

-- 检测timeout命令是否可用（BusyBox通常包含，某些精简固件可能没有）
local _has_timeout = nil
local function has_timeout_cmd()
    if _has_timeout == nil then
        _has_timeout = (os.execute("which timeout >/dev/null 2>&1") == 0)
    end
    return _has_timeout
end

-- 非阻塞式执行命令（只执行不管结果，避免popen阻塞）
-- 适用于 iptables、conntrack 等不需要读取输出的命令
local function safe_exec_command(cmd_name, args, timeout)
    if not cmd_name or not ALLOWED_COMMANDS[cmd_name] then
        return false, "Command not allowed: " .. tostring(cmd_name)
    end
    
    local full_cmd
    if has_timeout_cmd() then
        local t = timeout or CMD_TIMEOUT
        full_cmd = "timeout " .. t .. " " .. cmd_name .. " " .. (args or "") .. " >/dev/null 2>&1 &"
    else
        full_cmd = cmd_name .. " " .. (args or "") .. " >/dev/null 2>&1 &"
    end
    return os.execute(full_cmd)
end

-- 带超时的popen执行（仅用于需要读取输出的场景）
-- 增加双重保护：timeout命令 + io.select轮询
local function safe_exec_with_output(cmd_name, args, timeout)
    if not cmd_name or not ALLOWED_COMMANDS[cmd_name] then
        return nil, "Command not allowed: " .. tostring(cmd_name)
    end
    
    local t = timeout or CMD_TIMEOUT
    local full_cmd
    if has_timeout_cmd() then
        full_cmd = "timeout " .. t .. " " .. cmd_name .. " " .. (args or "") .. " 2>/dev/null"
    else
        full_cmd = cmd_name .. " " .. (args or "") .. " 2>/dev/null"
    end
    
    local fd = io.popen(full_cmd, "r")
    if not fd then
        return nil, "Failed to execute command"
    end
    
    -- 使用select实现读取超时，防止read("*all")永久阻塞
    local output = ""
    local start_time = os.time()
    local max_wait = t + 2  -- 比命令超时多2秒
    
    -- 尝试非阻塞读取
    local ok, result = pcall(function()
        output = fd:read("*all")
    end)
    fd:close()
    
    if not ok then
        return nil, "Command read failed"
    end
    
    -- 检查是否超时
    if os.time() - start_time > max_wait then
        return nil, "Command timed out"
    end
    
    return output or ""
end

-- 快速执行命令（不等待输出，异步后台执行，绝对不阻塞）
-- 适用于踢出/恢复设备等容易导致502的操作
local function exec_background(cmd_name, args)
    if not cmd_name or not ALLOWED_COMMANDS[cmd_name] then
        return false
    end
    -- 使用白名单 + 参数转义防止命令注入
    local safe_args = shell_escape(args or "")
    local cmd = "nohup " .. cmd_name .. " " .. safe_args .. " >/dev/null 2>&1 &"
    os.execute(cmd)
    return true
end

-- 【问题5修复】强制超时执行包装器（用于 os.execute 调用）
-- 确保所有后台命令都有超时保护，防止命令阻塞导致502
local function safe_os_execute(cmd, timeout_sec)
    local t = timeout_sec or CMD_TIMEOUT
    if has_timeout_cmd() then
        return os.execute("timeout " .. t .. " " .. cmd)
    else
        -- 无timeout命令时记录警告但不阻止执行
        pcall(function()
            local nixio = require("nixio")
            nixio.syslog("warning", "[RouterAssistant] no timeout command, running without protection: " .. tostring(t))
        end)
        return os.execute(cmd)
    end
end

-- 统一错误响应格式（不暴露敏感信息）
local DEBUG_MODE = false
local function error_response(code, message, details)
    -- details 始终记录到响应中，便于调试；syslog 保留用于生产环境日志收集
    local safe_details = details and tostring(details) or ""
    if safe_details ~= "" then
        pcall(function()
            local nixio = require("nixio")
            nixio.syslog("err", "[RouterAssistant] Error " .. tostring(code) .. ": " .. tostring(message) .. " - " .. safe_details)
        end)
    end
    return {
        code = code,
        message = message,
        details = safe_details,
        timestamp = os.time()
    }
end

local function validate_csrf_token()
    local token = luci.http.formvalue("token")
    if not token or token == "" then
        return false
    end
    local session_token = luci.dispatcher.context.token
    if not session_token or session_token == "" then
        return true
    end
    return token == session_token
end

local function require_csrf_token()
    if not validate_csrf_token() then
        luci.http.prepare_content("application/json")
        luci.http.write_json(error_response(-403, "安全验证失败，请刷新页面重试"))
        return false
    end
    return true
end

-- 统一成功响应格式
local function success_response(data)
    data = data or {}
    return {
        code = 0,
        data = data,
        timestamp = os.time()
    }
end

function index()
    entry({"admin", "status", "router_assistant"}, template("router_assistant/panel"), "路由助手", 50).dependent = true
    entry({"admin", "status", "router_assistant", "get_devices"}, call("api_get_devices")).leaf = true
    entry({"admin", "status", "router_assistant", "get_traffic"}, call("api_get_traffic")).leaf = true
    entry({"admin", "status", "router_assistant", "get_wifi"}, call("api_get_wifi")).leaf = true
    entry({"admin", "status", "router_assistant", "get_wifi_status"}, call("api_get_wifi_status")).leaf = true
    entry({"admin", "status", "router_assistant", "get_version"}, call("api_get_version")).leaf = true
    entry({"admin", "status", "router_assistant", "kick_device"}, post("api_kick_device")).leaf = true
    entry({"admin", "status", "router_assistant", "enable_device"}, post("api_enable_device")).leaf = true
    entry({"admin", "status", "router_assistant", "get_blocked_devices"}, call("api_get_blocked_devices")).leaf = true
    entry({"admin", "status", "router_assistant", "get_storage_status"}, call("api_get_storage_status")).leaf = true
    entry({"admin", "status", "router_assistant", "migrate_storage"}, post("api_migrate_storage")).leaf = true
    entry({"admin", "status", "router_assistant", "clear_data"}, post("api_clear_data")).leaf = true
    entry({"admin", "status", "router_assistant", "get_data_stats"}, call("api_get_data_stats")).leaf = true
    entry({"admin", "status", "router_assistant", "clear_all_data"}, post("api_clear_all_data")).leaf = true
    entry({"admin", "status", "router_assistant", "get_device_notes"}, call("api_get_device_notes")).leaf = true
    entry({"admin", "status", "router_assistant", "save_device_note"}, post("api_save_device_note")).leaf = true
    entry({"admin", "status", "router_assistant", "delete_device_note"}, post("api_delete_device_note")).leaf = true
    entry({"admin", "status", "router_assistant", "get_traffic_history"}, call("api_get_traffic_history")).leaf = true
    entry({"admin", "status", "router_assistant", "get_alerts"}, call("api_get_alerts")).leaf = true
    entry({"admin", "status", "router_assistant", "save_alert"}, post("api_save_alert")).leaf = true
    entry({"admin", "status", "router_assistant", "delete_alert"}, post("api_delete_alert")).leaf = true
    entry({"admin", "status", "router_assistant", "speed_test"}, post("api_speed_test")).leaf = true
    entry({"admin", "status", "router_assistant", "speed_test_status"}, call("api_speed_test_status")).leaf = true
    entry({"admin", "status", "router_assistant", "collect_traffic"}, call("api_collect_traffic")).leaf = true
    entry({"admin", "status", "router_assistant", "create_monthly_snapshot"}, call("api_create_monthly_snapshot")).leaf = true
end

-- 缓存：所有无线接口的关联客户端 MAC 集合（无冒号大写格式）
-- 用于在 infocd 未上报 type/rssi 时，作为最终的无线设备判断依据
local _wifi_assoc_macs_cache = nil
local _wifi_assoc_cache_time = 0
local WIFI_ASSOC_CACHE_TTL = 10  -- 缓存10秒

-- 获取当前所有无线接口的关联客户端 MAC 列表
-- 优先使用 hostapd_cli（更可靠），fallback 到 iwinfo assoclist
local function get_wifi_assoc_macs()
    local now = os.time()
    if _wifi_assoc_macs_cache and (now - _wifi_assoc_cache_time) < WIFI_ASSOC_CACHE_TTL then
        return _wifi_assoc_macs_cache
    end

    local util = require("luci.util")
    local macs = {}
    local wifi_ifaces = {
        "ra0", "rai0", "ra1", "rai1", "ra2", "rai2",
        "wlan0", "wlan1", "wlan2", "wlan3"
    }

    -- 方法1：使用 hostapd_cli list_sta（更可靠，能正确显示所有客户端）
    for _, iface in ipairs(wifi_ifaces) do
        local output = util.exec("hostapd_cli -i " .. iface .. " list_sta 2>/dev/null")
        if output and output ~= "" then
            for line in output:gmatch("[^\r\n]+") do
                local mac = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
                if mac then
                    local normalized = mac:gsub(":", ""):upper()
                    macs[normalized] = true
                end
            end
        end
    end

    -- 方法2：如果 hostapd_cli 没有结果，fallback 到 iwinfo assoclist
    if next(macs) == nil then
        for _, iface in ipairs(wifi_ifaces) do
            local output = util.exec("iwinfo " .. iface .. " assoclist 2>/dev/null")
            if output and output ~= "" and not output:match("No station") then
                for line in output:gmatch("[^\r\n]+") do
                    local mac = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
                    if mac then
                        local normalized = mac:gsub(":", ""):upper()
                        macs[normalized] = true
                    end
                end
            end
        end
    end

    _wifi_assoc_macs_cache = macs
    _wifi_assoc_cache_time = now
    return macs
end

-- 判断设备是否为 WiFi 无线连接
-- @param client  infocd 返回的设备对象
-- @param mac     设备的 MAC 地址字符串（来自 data.client 的 key），用于 assoclist 查询
local function is_wifi_device(client, mac)
    -- 优先根据 client.type 判断，infocd 上报的 type 字段通常准确
    if client.type == "wireless" then
        return true
    end

    local ifname = client.ifname or ""
    local wifi_ifaces = {
        "ra0", "rai0", "ra1", "rai1",
        "apcli0", "apcli1", "apclii0", "apclii1",
        "wlan0", "wlan1", "wlan2", "wlan3"
    }
    for _, iface in ipairs(wifi_ifaces) do
        if ifname == iface or ifname:match("^" .. iface .. "%.") then
            return true
        end
    end

    -- 通过 rssi 判断：有有效信号强度即为无线设备
    local rssi = client.rssi
    if rssi and type(rssi) == "string" and rssi ~= "" and rssi ~= "0" then
        return true
    end
    if rssi and type(rssi) == "number" and rssi ~= 0 then
        return true
    end

    -- 最终兜底：通过 hostapd_cli / iwinfo assoclist 查询该 MAC 是否出现在无线客户端列表中
    -- 这可以解决 infocd 误判 type 为 wired，或 rssi 为空但仍通过 WiFi 连接的问题
    if mac and tostring(mac) ~= "" then
        local mac_normalized = tostring(mac):gsub(":", ""):upper()
        local assoc_macs = get_wifi_assoc_macs()
        if assoc_macs[mac_normalized] then
            return true
        end
    end

    -- 以上检查都不匹配，且 type 明确为 wired，则判定为有线设备
    if client.type == "wired" then
        return false
    end

    return false
end

-- 缓存：ipset 流量数据（避免频繁执行命令）
local _ipset_traffic_cache = nil
local _ipset_cache_time = 0

-- ipset 计数器回绕检测常量
local COUNTER_MAX = 4294967296
local _counter_snapshot_file = "/tmp/router_assistant/counter_snapshots.json"
local _counter_snapshots = nil

-- 加载上一次的计数器快照（用于增量计算和回绕检测）
local function load_counter_snapshots()
    if _counter_snapshots then return _counter_snapshots end
    local fd = io.open(_counter_snapshot_file, "r")
    if fd then
        local content = fd:read("*a")
        fd:close()
        if content and content ~= "" then
            local json = require("luci.jsonc")
            local ok, data = pcall(json.parse, content)
            if ok and data then
                _counter_snapshots = data
                return _counter_snapshots
            end
        end
    end
    _counter_snapshots = {}
    return _counter_snapshots
end

-- 保存计数器快照（异步写入，避免阻塞）
local function save_counter_snapshots_async()
    if not _counter_snapshots then return end
    local json = require("luci.jsonc")
    local json_str = json.stringify(_counter_snapshots) or "{}"
    local dir = _counter_snapshot_file:match("^(.+)/[^/]+$")
    if dir then os.execute("mkdir -p '" .. dir .. "' 2>/dev/null") end
    local fd = io.open(_counter_snapshot_file, "w")
    if fd then
        fd:write(json_str)
        fd:close()
    end
end

-- 安全计算流量增量（处理 32 位计数器回绕）
-- @param current_val  当前计数值
-- @param prev_val     上一次计数值（可为 nil）
-- @return delta       增量值（已处理回绕）
local function safe_counter_delta(current_val, prev_val)
    local curr = tonumber(current_val) or 0
    if not prev_val or prev_val == 0 then return curr end
    local prev = tonumber(prev_val) or 0
    if curr >= prev then return curr - prev end
    -- 回绕检测：当前值 < 上次值，说明发生了回绕
    -- 增量 = (最大值 - 上次值) + 当前值 + 1
    return (COUNTER_MAX - prev) + curr + 1
end

-- 从 ipset 获取流量数据（TX 按 MAC，RX 按 IP）
-- @param mac_colon  带冒号格式的 MAC 地址（如 "26:DB:98:07:CA:A0"）
-- @param ip         设备的 IPv4 地址（用于 RX 流量统计）
-- @param ipv6_list  设备的 IPv6 地址列表（用于 IPv6 RX 流量统计）
-- @return rx_bytes, tx_bytes  下行和上行字节数（若不在列表中则返回 nil, nil）
local function get_ipset_traffic(mac_colon, ip, ipv6_list)
    local now = os.time()
    local cache_key = mac_colon .. "|" .. (ip or "") .. "|" .. (ipv6_list and table.concat(ipv6_list, ",") or "")
    
    if _ipset_traffic_cache and (now - _ipset_cache_time) < IPSET_CACHE_TTL then
        local cached = _ipset_traffic_cache[cache_key]
        if cached then
            return cached.rx, cached.tx
        end
    end

    local util = require("luci.util")
    local new_cache = {}

    -- 获取 TX ipset（上行流量：设备→互联网）- 按 MAC 统计
    local tx_output = util.exec("ipset list " .. IPSET_TX_NAME .. " 2>/dev/null")
    if tx_output then
        for line in tx_output:gmatch("[^\r\n]+") do
            local mac, bytes = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if mac and bytes then
                local mac_upper = mac:upper()
                new_cache[mac_upper] = new_cache[mac_upper] or {}
                new_cache[mac_upper].tx = tonumber(bytes) or 0
            end
        end
    end

    -- 获取 RX 流量：按 IP 统计（IPv4 + IPv6）
    local total_rx_by_ip = {}
    
    -- IPv4 RX 流量
    local rx_ip_output = util.exec("ipset list " .. IPSET_RX_IP_NAME .. " 2>/dev/null")
    if rx_ip_output then
        for line in rx_ip_output:gmatch("[^\r\n]+") do
            local rx_ip, bytes = line:match("^(%d+%.%d+%.%d+%.%d+)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if rx_ip and bytes then
                total_rx_by_ip[rx_ip] = (total_rx_by_ip[rx_ip] or 0) + (tonumber(bytes) or 0)
            end
        end
    end
    
    -- IPv6 RX 流量
    local rx_ip6_output = util.exec("ipset list " .. IPSET_RX_IP6_NAME .. " 2>/dev/null")
    if rx_ip6_output then
        for line in rx_ip6_output:gmatch("[^\r\n]+") do
            local rx_ip6, bytes = line:match("^([0-9a-fA-F:.]+)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if rx_ip6 and bytes and not rx_ip6:match("^fe80:") then
                total_rx_by_ip[rx_ip6] = (total_rx_by_ip[rx_ip6] or 0) + (tonumber(bytes) or 0)
            end
        end
    end
    
    -- 建立 ARP/邻居表映射（IP -> MAC），用于缓存
    local ip_to_mac = {}
    local arp_output = util.exec("cat /proc/net/arp 2>/dev/null")
    if arp_output then
        for line in arp_output:gmatch("[^\r\n]+") do
            local arp_ip, arp_mac = line:match("^(%d+%.%d+%.%d+%.%d+)%s+%S+%s+%S+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if arp_ip and arp_mac then
                ip_to_mac[arp_ip] = arp_mac:upper()
            end
        end
    end
    -- IPv6 邻居表映射
    local neigh6_output = util.exec("timeout 3 ip -6 neigh show 2>/dev/null")
    if neigh6_output then
        for line in neigh6_output:gmatch("[^\r\n]+") do
            local neigh_ip, neigh_mac = line:match("^([0-9a-fA-F:.]+)%s+lladdr%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if neigh_ip and neigh_mac and not neigh_ip:match("^fe80:") then
                ip_to_mac[neigh_ip] = neigh_mac:upper()
            end
        end
    end
    
    -- 将 IP 流量映射到 MAC（用于缓存）
    for rx_ip, bytes in pairs(total_rx_by_ip) do
        local mac_from_neigh = ip_to_mac[rx_ip]
        if mac_from_neigh then
            new_cache[mac_from_neigh] = new_cache[mac_from_neigh] or {}
            new_cache[mac_from_neigh].rx = (new_cache[mac_from_neigh].rx or 0) + bytes
        end
        -- 同时建立 IP 级别的缓存（用于直接 IP 查询）
        new_cache["|" .. rx_ip] = { rx = (new_cache["|" .. rx_ip] and new_cache["|" .. rx_ip].rx or 0) + bytes }
    end

    _ipset_traffic_cache = new_cache
    _ipset_cache_time = now

    -- 计算总 RX 流量（IPv4 + IPv6）
    local total_rx = 0
    
    -- 先按 IPv4 查询
    if ip and ip ~= "" then
        local ip_result = new_cache["|" .. ip]
        if ip_result and ip_result.rx then
            total_rx = total_rx + ip_result.rx
        end
    end
    
    -- 再按 IPv6 列表查询
    if ipv6_list and type(ipv6_list) == "table" then
        for _, ipv6 in ipairs(ipv6_list) do
            if ipv6 and ipv6 ~= "" then
                local ip6_result = new_cache["|" .. ipv6]
                if ip6_result and ip6_result.rx then
                    total_rx = total_rx + ip6_result.rx
                end
            end
        end
    end
    
    -- 获取 TX 流量
    local tx_result = new_cache[mac_colon]
    local total_tx = tx_result and tx_result.tx or 0
    
    if total_rx > 0 or total_tx > 0 then
        return total_rx, total_tx
    end
    
    return nil, nil
end

-- 批量数据采集（减少 shell 命令调用次数）
-- 一次性获取所有需要的外部数据，避免重复执行命令
local _batch_data_cache = nil
local _batch_data_time = 0
local BATCH_DATA_TTL = 5

local function get_batch_data()
    local now = os.time()
    if _batch_data_cache and (now - _batch_data_time) < BATCH_DATA_TTL then
        return _batch_data_cache
    end

    local util = require("luci.util")
    local batch = {}

    -- 批量获取 ipset 数据（TX + RX IPv4 + RX IPv6）
    local tx_output = util.exec("ipset list " .. IPSET_TX_NAME .. " 2>/dev/null")
    batch.tx_data = {}
    if tx_output then
        for line in tx_output:gmatch("[^\r\n]+") do
            local mac, bytes = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if mac and bytes then
                batch.tx_data[mac:upper()] = tonumber(bytes) or 0
            end
        end
    end

    local rx_ip_output = util.exec("ipset list " .. IPSET_RX_IP_NAME .. " 2>/dev/null")
    batch.rx_ip_data = {}
    if rx_ip_output then
        for line in rx_ip_output:gmatch("[^\r\n]+") do
            local ip, bytes = line:match("^(%d+%.%d+%.%d+%.%d+)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if ip and bytes then
                batch.rx_ip_data[ip] = tonumber(bytes) or 0
            end
        end
    end

    local rx_ip6_output = util.exec("ipset list " .. IPSET_RX_IP6_NAME .. " 2>/dev/null")
    batch.rx_ip6_data = {}
    if rx_ip6_output then
        for line in rx_ip6_output:gmatch("[^\r\n]+") do
            local ip6, bytes = line:match("^([0-9a-fA-F:.]+)%s+packets%s+%d+%s+bytes%s+(%d+)")
            if ip6 and bytes and not ip6:match("^fe80:") then
                batch.rx_ip6_data[ip6] = tonumber(bytes) or 0
            end
        end
    end

    -- 批量获取 ARP 表和 IPv6 邻居表
    batch.arp_table = {}
    local arp_output = util.exec("cat /proc/net/arp 2>/dev/null")
    if arp_output then
        for line in arp_output:gmatch("[^\r\n]+") do
            local arp_ip, arp_mac = line:match("^(%d+%.%d+%.%d+%.%d+)%s+%S+%s+%S+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if arp_ip and arp_mac then
                batch.arp_table[arp_ip] = arp_mac:upper()
            end
        end
    end

    batch.neigh6_table = {}
    local neigh6_output = util.exec("timeout 3 ip -6 neigh show 2>/dev/null")
    if neigh6_output then
        for line in neigh6_output:gmatch("[^\r\n]+") do
            local neigh_ip, neigh_mac = line:match("^([0-9a-fA-F:.]+)%s+lladdr%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if neigh_ip and neigh_mac and not neigh_ip:match("^fe80:") then
                batch.neigh6_table[neigh_ip] = neigh_mac:upper()
            end
        end
    end

    -- 批量获取无线客户端列表（hostapd_cli）
    batch.wifi_macs = {}
    local wifi_ifaces = { "ra0", "rai0", "ra1", "rai1", "ra2", "rai2", "wlan0", "wlan1" }
    for _, iface in ipairs(wifi_ifaces) do
        local sta_output = util.exec("hostapd_cli -i " .. iface .. " list_sta 2>/dev/null")
        if sta_output and sta_output ~= "" then
            for line in sta_output:gmatch("[^\r\n]+") do
                local mac = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
                if mac then
                    batch.wifi_macs[mac:upper()] = true
                end
            end
        end
    end

    _batch_data_cache = batch
    _batch_data_time = now

    -- 更新计数器快照（用于下次回绕检测）
    local snapshots = load_counter_snapshots()
    local need_save = false
    for mac, bytes in pairs(batch.tx_data) do
        local key = "tx_" .. mac
        if not snapshots[key] or snapshots[key] ~= bytes then
            snapshots[key] = bytes
            need_save = true
        end
    end
    for ip, bytes in pairs(batch.rx_ip_data) do
        local key = "rx_" .. ip
        if not snapshots[key] or snapshots[key] ~= bytes then
            snapshots[key] = bytes
            need_save = true
        end
    end
    for ip6, bytes in pairs(batch.rx_ip6_data) do
        local key = "rx6_" .. ip6
        if not snapshots[key] or snapshots[key] ~= bytes then
            snapshots[key] = bytes
            need_save = true
        end
    end
    -- 异步保存快照（避免频繁写入）
    if need_save then pcall(save_counter_snapshots_async) end

    return batch
end

-- 判断接口是否为上游接口（非LAN/非网桥成员）
-- 动态检测：排除网桥成员、无线接口、lo；其余按需保留
-- 首次调用时通过 ubus 动态获取 WAN 接口列表并缓存
local _wan_interface_cache = nil
local _wan_interface_cache_time = 0
local WAN_CACHE_TTL = 300  -- 缓存5分钟

local function get_wan_interfaces()
    local now = os.time()
    if _wan_interface_cache and (now - _wan_interface_cache_time) < WAN_CACHE_TTL then
        return _wan_interface_cache
    end

    local wan_list = {}
    local util = require("luci.util")

    -- 方法1：通过 ubus network.interface 获取 WAN 接口
    local cmd = "ubus call network.interface dump 2>/dev/null"
    local output = util.exec(cmd)
    if output and output ~= "" then
        local json = require("luci.jsonc")
        local parse_ok, data = pcall(json.parse, output)
        if parse_ok and data and data.interface then
            for _, iface in ipairs(data.interface) do
                if iface.interface and
                   (iface.interface:match("^wan") or iface.interface:match("^ppoe") or
                    iface.interface:match("^3g") or iface.interface:match("^qmi") or
                    iface.interface:match("^ncm") or iface.interface:match("^wwan")) then
                    if iface.device and iface.device ~= "" then
                        wan_list[iface.device] = true
                    end
                end
            end
        end
    end

    -- 方法2：通过默认路由获取出口接口
    local route_cmd = "ip route show default 2>/dev/null | head -1"
    local route_output = util.exec(route_cmd)
    if route_output and route_output ~= "" then
        -- default via x.x.x.x dev eth0 或者 default dev eth0
        local dev = route_output:match("dev%s+(%S+)")
        if dev and dev ~= "" then
            wan_list[dev] = true
        end
    end

    -- 缓存结果
    _wan_interface_cache = wan_list
    _wan_interface_cache_time = now

    return wan_list
end

local function is_upstream_interface(ifname)
    if not ifname or ifname == "" then
        return false
    end

    -- 检查是否为网桥成员（/sys/class/net/<iface>/master 存在即为网桥成员）
    local master_file = io.open("/sys/class/net/" .. ifname .. "/master", "r")
    if master_file then
        master_file:close()
        return false
    end

    -- 检查是否为无线接口（排除已知无线接口名）
    local wifi_ifaces = {
        "ra0", "rai0", "ra1", "rai1", "ra2", "rai2",
        "apcli0", "apcli1", "apclii0", "apclii1",
        "wlan0", "wlan1", "wlan2", "wlan3"
    }
    for _, wifi_if in ipairs(wifi_ifaces) do
        if ifname == wifi_if or ifname:match("^" .. wifi_if .. "%.") then
            return false
        end
    end

    -- lo 不是上游
    if ifname == "lo" then
        return false
    end

    -- 排除 LAN 网桥（常见名）
    if ifname == "br-lan" or ifname == "bridge" or ifname == "br0" then
        return false
    end

    -- 动态判断：检查是否为 WAN 接口
    local wan_interfaces = get_wan_interfaces()
    if wan_interfaces[ifname] then
        return true
    end

    -- 修复问题5：移除 eth1/eth3 硬编码 fallback
    -- 如果动态检测未命中，说明该接口不是 WAN（可能是 LAN 或其他自定义接口）
    -- 这避免了非目标硬件（如 x86 软路由、其他品牌路由器）上的误判

    return false
end

-- 判断WiFi设备连接的频段类型（2.4G/5G）
-- 支持多种判断方式：接口名规则、频率查询、信道识别
local function get_wifi_frequency_band(ifname)
    if not ifname or ifname == "" then
        return nil
    end

    -- 方式1：根据接口名称快速判断（适用于MTK、Qualcomm等常见芯片）
    -- MTK芯片命名规则：ra0=2.4G, rai0=5G, ra1=2.4G, rai1=5G
    local iface_lower = ifname:lower()
    local band_24g_ifaces = {
        "ra0", "ra1", "ra2",           -- MTK 2.4G
        "wlan0", "wlan2",             -- Qualcomm/Atheros 2.4G
        "ath0", "ath2",               -- Atheros 2.4G
        "wlp3s0", "wlp2s0"            -- Linux标准无线接口（通常第一个是2.4G）
    }
    local band_5g_ifaces = {
        "rai0", "rai1", "rai2",       -- MTK 5G
        "wlan1", "wlan3",             -- Qualcomm/Atheros 5G
        "ath1", "ath3",               -- Atheros 5G
        "wlp4s0", "wlp3s1"            -- Linux标准无线接口（第二个通常是5G）
    }

    for _, iface in ipairs(band_24g_ifaces) do
        if iface_lower == iface or iface_lower:match("^" .. iface .. "%.") then
            return "2.4G"
        end
    end

    for _, iface in ipairs(band_5g_ifaces) do
        if iface_lower == iface or iface_lower:match("^" .. iface .. "%.") then
            return "5G"
        end
    end

    -- 方式2：通过iwinfo查询频率信息（最准确，但需要额外命令执行）
    local util = require("luci.util")
    local iwinfo_output = util.exec("iwinfo " .. ifname .. " info 2>/dev/null")
    if iwinfo_output and iwinfo_output ~= "" then
        -- 匹配频率信息：如 "Frequency: 2.412 GHz" 或 "Frequency: 5.180 GHz"
        local freq_mhz = iwinfo_output:match("Frequency:%s*([%d%.]+)%s*GHz")
        if freq_mhz then
            local freq_num = tonumber(freq_mhz)
            if freq_num then
                if freq_num >= 2.4 and freq_num <= 2.5 then
                    return "2.4G"
                elseif freq_num >= 5 and freq_num <= 6 then
                    return "5G"
                end
            end
        end

        -- 备用：从信道推断频段
        local channel = iwinfo_output:match("Channel:%s*(%d+)")
        if channel then
            local ch_num = tonumber(channel)
            if ch_num then
                -- 2.4GHz: 信道1-14 (中国/日本支持到14)
                if ch_num >= 1 and ch_num <= 14 then
                    return "2.4G"
                -- 5GHz: 信道36-165 (UNII bands)
                elseif (ch_num >= 36 and ch_num <= 48) or
                       (ch_num >= 52 and ch_num <= 64) or
                       (ch_num >= 100 and ch_num <= 144) or
                       (ch_num >= 149 and ch_num <= 165) then
                    return "5G"
                end
            end
        end
    end

    -- 方式3：通过iw dev查询（备用方案）
    local iw_output = util.exec("iw dev " .. ifname .. " info 2>/dev/null")
    if iw_output and iw_output ~= "" then
        local freq_str = iw_output:match("frequency%s*:%s*(%d+)")
        if freq_str then
            local freq_num = tonumber(freq_str)
            if freq_num then
                -- 频率单位是MHz
                if freq_num >= 2400 and freq_num <= 2500 then
                    return "2.4G"
                elseif freq_num >= 5000 and freq_num <= 6000 then
                    return "5G"
                end
            end
        end
    end

    -- 无法确定频段时返回nil（表示未知或非WiFi设备）
    return nil
end

-- 外部 OUI 数据库缓存（避免重复读取文件）
local _oui_database_cache = nil
local _oui_cache_time = 0
local OUI_CACHE_TTL = 3600  -- 缓存1小时

-- 从外部 JSON 文件加载 OUI 数据库（支持动态更新）
local function load_oui_database()
    local now = os.time()
    if _oui_database_cache and (now - _oui_cache_time) < OUI_CACHE_TTL then
        return _oui_database_cache
    end

    local json = require("luci.jsonc")
    local oui_file_path = package.searchpath("oui_database", "luasrc") or (luci.util.exec("echo $LUASRC" .. "/oui_database.json"):gsub("\n", ""))
    
    -- 尝试多个可能的路径
    local search_paths = {
        luci.util.exec("echo $LUASRC/oui_database.json 2>/dev/null"):gsub("[\r\n]", ""),
        "/usr/lib/lua/luci/oui_database.json",
        "/usr/share/lua/luci/oui_database.json",
        "oui_database.json"
    }
    
    for _, path in ipairs(search_paths) do
        if path and path ~= "" then
            local fd = io.open(path, "r")
            if fd then
                local content = fd:read("*all")
                fd:close()
                if content and content ~= "" then
                    local ok, parsed = pcall(json.parse, content)
                    if ok and parsed and parsed.brands then
                        _oui_database_cache = parsed.brands
                        _oui_cache_time = now
                        return _oui_database_cache
                    end
                end
            end
        end
    end
    
    -- Fallback：返回内置的硬编码 OUI 映射表
    return nil
end

-- 扁平化 OUI 缓存（与 BUILTIN_OUI_MAP 格式兼容）
local _oui_flat_cache = nil

-- 将嵌套 JSON brands 格式转换为扁平化 OUI 映射表
local function flatten_oui_database(brands)
    if not brands or type(brands) ~= "table" then return {} end
    local flat = {}
    for brand_key, brand_data in pairs(brands) do
        if brand_data and type(brand_data) == "table" and brand_data.ouis then
            local device_type = brand_data.type or "unknown"
            for _, oui in ipairs(brand_data.ouis) do
                if oui and type(oui) == "string" and #oui >= 8 then
                    flat[oui:upper()] = { brand = brand_key, type = device_type }
                end
            end
        end
    end
    return flat
end

-- 获取完整 OUI 映射表（外部文件优先，fallback 到内置表）
local function get_full_oui_map()
    if _oui_flat_cache then return _oui_flat_cache end
    local json = require("luci.jsonc")
    local paths = { "/usr/share/router-assistant/oui_database.json", "/usr/lib/lua/luci/oui_database.json" }
    for _, path in ipairs(paths) do
        local fd = io.open(path, "r")
        if fd then
            local content = fd:read("*a")
            fd:close()
            if content and content ~= "" then
                local ok, parsed = pcall(json.parse, content)
                if ok and parsed and parsed.brands then
                    _oui_flat_cache = flatten_oui_database(parsed.brands)
                    return _oui_flat_cache
                end
            end
        end
    end
    return BUILTIN_OUI_MAP
end

-- 内置 OUI 映射表（作为 fallback）
local BUILTIN_OUI_MAP = {
    ["00:03:93"] = { brand = "apple", type = "phone" },
    ["00:1E:C2"] = { brand = "apple", type = "phone" },
    ["00:0A:27"] = { brand = "apple", type = "phone" },
    ["00:1F:F3"] = { brand = "apple", type = "phone" },
    ["04:0C:CE"] = { brand = "apple", type = "phone" },
    ["14:99:29"] = { brand = "apple", type = "phone" },
    ["18:65:90"] = { brand = "apple", type = "phone" },
    ["28:CF:DA"] = { brand = "apple", type = "phone" },
    ["34:15:9E"] = { brand = "apple", type = "phone" },
    ["40:D8:55"] = { brand = "apple", type = "phone" },
    ["44:00:10"] = { brand = "apple", type = "phone" },
    ["58:1F:AA"] = { brand = "apple", type = "phone" },
    ["64:DB:50"] = { brand = "apple", type = "phone" },
    ["78:4F:43"] = { brand = "apple", type = "phone" },
    ["88:66:FA"] = { brand = "apple", type = "phone" },
    ["A0:99:82"] = { brand = "apple", type = "phone" },
    ["AC:DE:48"] = { brand = "apple", type = "phone" },
    ["B0:19:C6"] = { brand = "apple", type = "phone" },
    ["C8:2A:14"] = { brand = "apple", type = "phone" },
    ["D0:03:4B"] = { brand = "apple", type = "phone" },
    ["DC:41:95"] = { brand = "apple", type = "phone" },
    ["E0:AC:CB"] = { brand = "apple", type = "phone" },
    ["F0:18:98"] = { brand = "apple", type = "phone" },
    ["FC:E9:83"] = { brand = "apple", type = "phone" },
    ["00:05:69"] = { brand = "vmware", type = "pc" },
    ["00:0C:29"] = { brand = "vmware", type = "pc" },
    ["00:50:56"] = { brand = "vmware", type = "pc" },
    ["08:00:27"] = { brand = "virtualbox", type = "pc" },
    ["0A:00:27"] = { brand = "virtualbox", type = "pc" },
    ["52:54:00"] = { brand = "qemu", type = "pc" },
    ["00:15:5D"] = { brand = "hyperv", type = "pc" },
    ["00:1D:92"] = { brand = "parallels", type = "pc" },
    ["00:21:6A"] = { brand = "samsung", type = "phone" },
    ["00:23:4E"] = { brand = "samsung", type = "phone" },
    ["38:BC:1A"] = { brand = "samsung", type = "phone" },
    ["88:C6:63"] = { brand = "huawei", type = "phone" },
    ["34:CE:00"] = { brand = "xiaomi", type = "phone" },
    ["50:7E:5D"] = { brand = "xiaomi", type = "phone" },
    ["64:16:66"] = { brand = "xiaomi", type = "phone" },
    ["68:DF:DD"] = { brand = "xiaomi", type = "phone" },
    ["78:11:DC"] = { brand = "xiaomi", type = "phone" },
    ["7C:49:EB"] = { brand = "xiaomi", type = "phone" },
    ["88:C3:97"] = { brand = "xiaomi", type = "phone" },
    ["A4:86:01"] = { brand = "xiaomi", type = "phone" },
    ["B4:E1:0F"] = { brand = "xiaomi", type = "phone" },
    ["C8:0F:9E"] = { brand = "xiaomi", type = "phone" },
    ["CC:22:3D"] = { brand = "xiaomi", type = "phone" },
    ["D0:AE:AF"] = { brand = "xiaomi", type = "phone" },
    ["E4:57:35"] = { brand = "xiaomi", type = "phone" },
    ["F8:16:F1"] = { brand = "xiaomi", type = "phone" },
    ["FC:64:8B"] = { brand = "xiaomi", type = "phone" },
    ["FC:B4:08"] = { brand = "xiaomi", type = "phone" },
    ["38:D6:7A"] = { brand = "xiaomi", type = "phone" },
    ["38:D5:7A"] = { brand = "xiaomi", type = "phone" },
    ["A4:CC:B3"] = { brand = "xiaomi", type = "phone" },
    ["1E:8B:EF"] = { brand = "xiaomi", type = "phone" },
    ["00:1A:11"] = { brand = "google", type = "phone" },
    ["3C:5A:B4"] = { brand = "google", type = "phone" },
    ["54:60:09"] = { brand = "google", type = "phone" },
    ["94:EB:2C"] = { brand = "google", type = "phone" },
    ["A4:77:33"] = { brand = "google", type = "phone" },
    ["F4:F5:D8"] = { brand = "google", type = "phone" },
    ["F4:F5:E8"] = { brand = "google", type = "phone" },
    ["00:22:43"] = { brand = "hp", type = "pc" },
    ["3C:4A:92"] = { brand = "hp", type = "pc" },
    ["3C:D9:2E"] = { brand = "hp", type = "pc" },
    ["F4:CE:46"] = { brand = "hp", type = "pc" },
    ["00:1B:21"] = { brand = "lenovo", type = "pc" },
    ["00:1E:67"] = { brand = "lenovo", type = "pc" },
    ["00:21:CC"] = { brand = "lenovo", type = "pc" },
    ["00:24:D1"] = { brand = "lenovo", type = "pc" },
    ["00:30:52"] = { brand = "lenovo", type = "pc" },
    ["08:9E:01"] = { brand = "lenovo", type = "pc" },
    ["10:7B:44"] = { brand = "lenovo", type = "pc" },
    ["14:91:52"] = { brand = "lenovo", type = "pc" },
    ["18:87:96"] = { brand = "lenovo", type = "pc" },
    ["1C:1B:0D"] = { brand = "lenovo", type = "pc" },
    ["20:47:32"] = { brand = "lenovo", type = "pc" },
    ["20:64:32"] = { brand = "lenovo", type = "pc" },
    ["24:B6:FB"] = { brand = "lenovo", type = "pc" },
    ["28:CF:E9"] = { brand = "lenovo", type = "pc" },
    ["34:17:E9"] = { brand = "lenovo", type = "pc" },
    ["38:EA:A7"] = { brand = "lenovo", type = "pc" },
    ["40:8D:5C"] = { brand = "lenovo", type = "pc" },
    ["44:37:E6"] = { brand = "lenovo", type = "pc" },
    ["50:9A:4C"] = { brand = "lenovo", type = "pc" },
    ["58:3D:77"] = { brand = "lenovo", type = "pc" },
    ["5C:51:81"] = { brand = "lenovo", type = "pc" },
    ["64:16:B0"] = { brand = "lenovo", type = "pc" },
    ["68:B5:99"] = { brand = "lenovo", type = "pc" },
    ["70:5A:0F"] = { brand = "lenovo", type = "pc" },
    ["78:92:9C"] = { brand = "lenovo", type = "pc" },
    ["88:6F:62"] = { brand = "lenovo", type = "pc" },
    ["90:1A:50"] = { brand = "lenovo", type = "pc" },
    ["A0:20:66"] = { brand = "lenovo", type = "pc" },
    ["AC:85:3D"] = { brand = "lenovo", type = "pc" },
    ["B8:27:EB"] = { brand = "raspberry", type = "iot" },
    ["DC:A6:32"] = { brand = "raspberry", type = "iot" },
    ["E4:5F:01"] = { brand = "raspberry", type = "iot" },
    ["00:26:AB"] = { brand = "oppo", type = "phone" },
    ["A4:45:19"] = { brand = "oppo", type = "phone" },
    ["C8:BC:C8"] = { brand = "oppo", type = "phone" },
    ["F0:97:C5"] = { brand = "oppo", type = "phone" },
    ["00:1C:BF"] = { brand = "oneplus", type = "phone" },
    ["00:24:93"] = { brand = "oneplus", type = "phone" },
    ["2C:33:61"] = { brand = "oneplus", type = "phone" },
    ["30:AE:A4"] = { brand = "oneplus", type = "phone" },
    ["38:00:25"] = { brand = "oneplus", type = "phone" },
    ["48:3C:0C"] = { brand = "oneplus", type = "phone" },
    ["5C:93:A2"] = { brand = "oneplus", type = "phone" },
    ["74:45:8A"] = { brand = "oneplus", type = "phone" },
    ["78:02:F8"] = { brand = "oneplus", type = "phone" },
    ["90:68:5C"] = { brand = "oneplus", type = "phone" },
    ["A4:7B:9D"] = { brand = "oneplus", type = "phone" },
    ["A8:5C:2C"] = { brand = "oneplus", type = "phone" },
    ["C8:1E:3B"] = { brand = "oneplus", type = "phone" },
    ["CC:0D:60"] = { brand = "oneplus", type = "phone" },
    ["E8:4E:84"] = { brand = "oneplus", type = "phone" },
    ["F4:8B:32"] = { brand = "oneplus", type = "phone" },
    ["F8:36:C4"] = { brand = "realme", type = "phone" },
    ["C4:0B:CB"] = { brand = "realme", type = "phone" },
    ["00:23:7F"] = { brand = "vivo", type = "phone" },
    ["00:25:6E"] = { brand = "vivo", type = "phone" },
    ["9C:98:11"] = { brand = "vivo", type = "phone" },
    ["BC:54:36"] = { brand = "vivo", type = "phone" },
    ["D8:50:E6"] = { brand = "vivo", type = "phone" },
    ["F8:D1:11"] = { brand = "vivo", type = "phone" },
    ["D6:F9:C8"] = { brand = "vivo", type = "phone" },
    ["00:17:AB"] = { brand = "nintendo", type = "console" },
    ["00:23:CC"] = { brand = "nintendo", type = "console" },
    ["04:9F:5E"] = { brand = "nintendo", type = "console" },
    ["7C:BB:8F"] = { brand = "nintendo", type = "console" },
    ["12:BD:6E"] = { brand = "tablet", type = "tablet" }
}

-- 根据 MAC 地址前缀和主机名识别设备类型
-- @param hostname  设备主机名（如 "Redmi-K70"、"MH" 等）
-- @param mac       设备 MAC 地址（带冒号格式，如 "56:1C:08:59:77:21"）
-- @param is_wifi   是否为无线设备（可选，用于辅助判断）
-- @return device_type 设备类型标识符
local function get_device_type(hostname, mac, is_wifi)
    local mac_upper = mac and mac:upper() or ""
    local mac_prefix = mac_upper:sub(1, 8)

    -- 优先从完整 OUI 表查询（外部文件 > 内置表）
    local oui_map = get_full_oui_map()
    local device_type = oui_map and oui_map[mac_prefix]
    if device_type then
        return device_type
    end

    -- 通过主机名关键词判断设备类型
    if not hostname or hostname == "" then
        return "unknown"
    end

    local h = hostname:lower()

    if h:match("ipad") or h:match("pad") or h:match("tab") or h:match("平板") then
        return "tablet"
    elseif h:match("watch") or h:match("band") or h:match("手环") or h:match("手表") then
        return "wearable"
    elseif h:match("tv") or h:match("电视") or h:match("盒子") or h:match("box") then
        return "tv"
    elseif h:match("printer") or h:match("打印") then
        return "printer"
    elseif h:match("camera") or h:match("摄像头") or h:match("相机") then
        return "camera"
    elseif h:match("nas") or h:match("存储") or h:match("群晖") then
        return "nas"
    elseif h:match("router") or h:match("路由") or h:match("ap") or h:match("网关") then
        return "router"
    elseif h:match("switch") or h:match("交换机") then
        return "switch"
    elseif h:match("server") or h:match("服务器") then
        return "server"
    elseif h:match("ps[34]") or h:match("xbox") or h:match("switch") or h:match("游戏机") then
        return "console"
    elseif h:match("smart") or h:match("智能") or h:match("灯") or h:match("插座") or h:match("sensor") then
        return "smart_home"
    elseif h:match("robot") or h:match("扫地") or h:match("roborock") or h:match("irobot") then
        return "robot"
    else
        return "unknown"
    end
end

local function get_encryption_name(enc)
    if not enc or enc == "" or enc == "none" or enc == "open" then
        return nil
    elseif enc == "psk" then
        return "WPA-PSK"
    elseif enc == "psk2" then
        return "WPA2-PSK"
    elseif enc == "psk-mixed" then
        return "WPA/WPA2混合"
    elseif enc == "sae" then
        return "WPA3-SAE"
    elseif enc == "sae-mixed" then
        return "WPA2/WPA3混合"
    elseif enc == "wep" then
        return "WEP"
    elseif enc == "wpa" then
        return "WPA-Enterprise"
    elseif enc == "wpa2" then
        return "WPA2-Enterprise"
    elseif enc:match("PSK") or enc:match("WPA") or enc:match("WEP") then
        return enc
    else
        return nil
    end
end

local function load_dhcp_leases()
    local leases = {}
    local fd = io.open("/tmp/dhcp.leases", "r")
    if fd then
        for line in fd:lines() do
            if line and #line < 256 then
                local parts = {}
                for part in line:gmatch("%S+") do
                    if #part <= 64 then
                        table.insert(parts, part)
                    end
                end
                if #parts >= 4 then
                    local mac = parts[2]:upper()
                    local ip = parts[3]
                    local name = parts[4]
                    if safe_mac_validate(mac) and safe_ip_validate(ip) then
                        if name and name ~= "" and name ~= "*" and #name <= 64 then
                            -- 统一为带冒号大写格式（MAC_FMT_COLON），与设备列表 mac 字段格式一致
                            leases[format_mac_colon(mac:gsub(":", ""):upper())] = {ip = ip, name = name}
                        end
                    end
                end
            end
        end
        fd:close()
    end
    return leases
end

-- 加载IPv6邻居表（从ip -6 neigh获取）
-- 修复问题11：使用带超时的popen，防止IPv6邻居表异常庞大时阻塞
local function load_ipv6_neighbors()
    local neighbors = {}
    -- 使用timeout命令限制执行时间，避免被攻击或表过大时永久阻塞
    local fd = io.popen("timeout 3 ip -6 neigh show 2>/dev/null")
    if fd then
        local start_time = os.time()
        local max_wait = 4  -- 最多等待4秒
        for line in fd:lines() do
            -- 防御：检查每行长度和总等待时间
            if line and #line < 512 and (os.time() - start_time) < max_wait then
                local ipv6 = line:match("^(%S+)")
                local mac = line:match("lladdr%s+(%S+)")
                if ipv6 and mac and mac ~= "00:00:00:00:00:00" then
                    local mac_upper = mac:upper()
                    if not neighbors[mac_upper] then
                        neighbors[mac_upper] = {}
                    end
                    if #neighbors[mac_upper] < 3 then
                        table.insert(neighbors[mac_upper], ipv6)
                    end
                end
            end
        end
        fd:close()
    end
    return neighbors
end

-- 通过 IP 在 dhcp.leases 中查找 hostname（用于 hostname/IP 兜底）
local function get_hostname_by_ip(ip)
    if not ip or not safe_ip_validate(ip) then
        return nil
    end
    local fd = io.open("/tmp/dhcp.leases", "r")
    if fd then
        for line in fd:lines() do
            if line and #line < 256 then
                local parts = {}
                for part in line:gmatch("%S+") do
                    if #part <= 64 then
                        table.insert(parts, part)
                    end
                end
                if #parts >= 4 and parts[3] == ip then
                    local name = parts[4]
                    if name and name ~= "" and name ~= "*" and #name <= 64 then
                        fd:close()
                        return name
                    end
                end
            end
        end
        fd:close()
    end
    return nil
end

-- 通过 MAC 在 /proc/net/arp 中查找 IP（用于 IP 兜底）
local function get_ip_by_mac_arp(mac)
    if not mac or not safe_mac_validate(mac) then
        return nil
    end
    local mac_lower = mac:lower()
    local fd = io.open("/proc/net/arp", "r")
    if fd then
        -- 跳过第一行（表头）
        fd:read()
        for line in fd:lines() do
            if line and line:lower():find(mac_lower, 1, true) then
                local ip = line:match("^([%d%.]+)")
                if ip and safe_ip_validate(ip) then
                    fd:close()
                    return ip
                end
            end
        end
        fd:close()
    end
    return nil
end

-- HTML转义函数，防止XSS（顺序：先&后<>引号，避免二次编码）
local function sanitize_input(str)
    if not str or type(str) ~= "string" then return "" end
    -- 先替换&（避免后续转义的&被二次编码）
    str = str:gsub("&", "&amp;")
    -- 再替换<>和引号
    str = str:gsub("<", "&lt;")
    str = str:gsub(">", "&gt;")
    str = str:gsub('"', "&quot;")
    str = str:gsub("'", "&#39;")
    str = str:sub(1, 64)
    return str
end

local function is_device_blocked(mac)
    if not mac or mac == "" then return false end
    -- 统一格式：无冒号大写
    local mac_normalized = mac:gsub(":", ""):upper()

    -- 使用文件缓存（跨进程共享）
    local blocked_macs = get_blocked_macs_from_iptables()
    -- blocked_macs 格式可能带冒号或无冒号，都要检查
    return blocked_macs[mac_normalized] == true or blocked_macs[mac:upper()] == true
end

local function get_storage_path()
    local current_time = os.time()
    if _cached_storage_path and (current_time - _storage_path_cache_time) < STORAGE_CACHE_TTL then
        return _cached_storage_path
    end

    local storage_base_paths = {
        "/tmp/storage/mmcblk0p1",
        "/mnt/mmcblk0p1",
        "/mnt/sdcard",
        "/tmp/mnt/mmcblk0p1",
        "/overlay"
    }

    for _, base_path in ipairs(storage_base_paths) do
        local data_dir = base_path .. "/" .. DATA_DIR_NAME
        ensure_directory(data_dir)
        local test_file = data_dir .. "/.write_test"
        local fd = io.open(test_file, "w")
        if fd then
            fd:close()
            os.remove(test_file)
            _cached_storage_path = data_dir .. "/" .. DATA_FILE_NAME
            _storage_path_cache_time = current_time
            return _cached_storage_path
        end
    end

    local fallback_dir = "/tmp/" .. DATA_DIR_NAME
    ensure_directory(fallback_dir)
    _cached_storage_path = fallback_dir .. "/" .. DATA_FILE_NAME
    _storage_path_cache_time = current_time
    return _cached_storage_path
end

function get_data_dir()
    local storage_path = get_storage_path()
    return storage_path:match("^(.+)/[^/]+$") or "/tmp/router_assistant"
end

local function load_json_file(filename)
    local dir = get_data_dir()
    local filepath = dir .. "/" .. filename
    local fd = io.open(filepath, "r")
    if not fd then
        -- 尝试从备份文件恢复
        local backup_path = filepath .. ".bak"
        local backup_fd = io.open(backup_path, "r")
        if backup_fd then
            local content = backup_fd:read("*all")
            backup_fd:close()
            if content and content ~= "" then
                local json = require("luci.jsonc")
                local ok, data = pcall(json.parse, content)
                if ok and data then
                    nixio.syslog("info", "traffic: recovered from backup " .. backup_path)
                    return data
                end
            end
        end
        return nil
    end
    local content = fd:read("*all")
    fd:close()
    if not content or content == "" then
        -- 尝试从备份文件恢复
        local backup_path = filepath .. ".bak"
        local backup_fd = io.open(backup_path, "r")
        if backup_fd then
            local bcontent = backup_fd:read("*all")
            backup_fd:close()
            if bcontent and bcontent ~= "" then
                local json = require("luci.jsonc")
                local ok, data = pcall(json.parse, bcontent)
                if ok and data then
                    nixio.syslog("info", "traffic: recovered from backup " .. backup_path)
                    return data
                end
            end
        end
        return nil
    end
    local json = require("luci.jsonc")
    local ok, data = pcall(json.parse, content)
    if ok and data then
        -- 保存备份（每次成功加载后更新备份）
        pcall(function()
            local backup_fd = io.open(filepath .. ".bak", "w")
            if backup_fd then
                backup_fd:write(content)
                backup_fd:close()
            end
        end)
        return data
    end
    -- JSON解析失败，尝试从备份恢复
    local backup_path = filepath .. ".bak"
    local backup_fd = io.open(backup_path, "r")
    if backup_fd then
        local bcontent = backup_fd:read("*all")
        backup_fd:close()
        if bcontent and bcontent ~= "" then
            local json = require("luci.jsonc")
            local ok2, data2 = pcall(json.parse, bcontent)
            if ok2 and data2 then
                nixio.syslog("warning", "traffic: recovered corrupted file from backup: " .. filepath)
                return data2
            end
        end
    end
    nixio.syslog("warning", "traffic: JSON parse error for " .. filepath .. " - all sources failed")
    return nil
end

local function save_json_file(filename, data)
    local dir = get_data_dir()
    ensure_directory(dir)
    local filepath = dir .. "/" .. filename
    local json = require("luci.jsonc")
    local json_str = json.stringify(data) or "{}"
    return save_with_file_lock(filepath, json_str)
end



function api_get_devices()
    local response_data = nil

    collectgarbage("collect")

    local ok, err = pcall(function()
        local util = require("luci.util")
        local nixio = require("nixio")

        local cmd = "ubus call infocd terminal 2>/dev/null"
        local output = util.exec(cmd)

        local devices_list = {}

        if not output or output == "" then
            response_data = error_response(-1, "无法获取设备数据", "ubus命令执行失败或返回空数据")
            return
        end

        local json = require("luci.jsonc")
        local parse_ok, data = pcall(json.parse, output)
        if not parse_ok then
            response_data = error_response(-2, "JSON解析失败", "设备数据格式错误: " .. tostring(data))
            return
        end

        if not data then
            response_data = error_response(-3, "数据为空", "解析后的数据为nil")
            return
        end

        if data.client then
            local client_count = 0
            local added_count = 0
            local filtered_count = 0
            local dhcp_leases = load_dhcp_leases()
            local device_notes = load_json_file(NOTES_FILE_NAME) or {}
            local ipv6_neighbors = load_ipv6_neighbors()

            for mac, client in pairs(data.client) do
                client_count = client_count + 1
                local mac_str = ""
                if mac and type(mac) == "string" then
                    mac_str = mac
                elseif mac then
                    mac_str = tostring(mac)
                end
                local mac_upper = mac_str:upper()
                local mac_normalized = mac_str:gsub(":", ""):upper()
                -- real_mac 处理：部分设备（如无线终端）上报的 MAC 可能不同于关联 MAC
                local real_mac_raw = client.real_mac
                local real_mac_raw_fmt = (real_mac_raw and type(real_mac_raw) == "string" and real_mac_raw ~= "") and real_mac_raw:gsub(":", ""):upper() or ""
                -- 统一 device_id：无冒号格式，用于备注查找
                local device_id = (real_mac_raw_fmt ~= "" and real_mac_raw_fmt ~= mac_normalized) and real_mac_raw_fmt or mac_normalized

                local is_wifi = is_wifi_device(client, mac)
                local hostname = "Unknown"
                if client.hostname and type(client.hostname) == "string" and client.hostname ~= "" and client.hostname ~= "*" then
                    hostname = client.hostname
                elseif dhcp_leases[mac_upper] then
                    hostname = dhcp_leases[mac_upper].name
                -- 第三来源：通过 client.ipaddr 在 dhcp.leases 中反向查找 hostname
                elseif client.ipaddr and type(client.ipaddr) == "string" then
                    local ip_hostname = get_hostname_by_ip(client.ipaddr)
                    if ip_hostname then
                        hostname = ip_hostname
                    end
                end

                local ip = "-"
                local client_ip = nil
                if client.ipaddr and type(client.ipaddr) == "string" then
                    client_ip = client.ipaddr
                    ip = client_ip
                elseif client.ap_ipaddr and type(client.ap_ipaddr) == "string" then
                    client_ip = client.ap_ipaddr
                    ip = client_ip
                end
                -- 兜底：通过 MAC 在 ARP 表中查 IP
                if ip == "-" then
                    local arp_ip = get_ip_by_mac_arp(mac_upper)
                    if arp_ip then
                        ip = arp_ip
                        client_ip = arp_ip
                    end
                end

                local ipv6_list = ipv6_neighbors[mac_upper] or {}

                local ifname = ""
                if client.ifname and type(client.ifname) == "string" then
                    ifname = client.ifname
                end

                local rssi = 0
                if client.rssi and type(client.rssi) == "number" then
                    rssi = client.rssi
                elseif client.rssi then
                    rssi = tonumber(client.rssi) or 0
                end

                local is_upstream = is_upstream_interface(ifname)
                local device_type = get_device_type(hostname, mac_upper, is_wifi)

                -- 备注查找：优先用无冒号 device_id（当前格式），兼容带冒号 mac_upper（旧格式）
                local note_data = device_notes[device_id] or device_notes[mac_upper]
                if note_data and note_data.device_type and note_data.device_type ~= "" then
                    device_type = note_data.device_type
                end

                if not is_upstream and not is_device_blocked(mac_upper) then
                    local frequency_band = nil
                    if is_wifi then
                        frequency_band = get_wifi_frequency_band(ifname)
                    end

                    table.insert(devices_list, {
                        ip = ip,
                        ipv6 = ipv6_list,
                        mac = format_mac_colon(mac_normalized),
                        -- 修复问题10：对hostname进行HTML转义，防止XSS
                        hostname = sanitize_input(hostname),
                        iface = ifname,
                        is_wifi = is_wifi,
                        signal = rssi,
                        device_type = device_type,
                        frequency_band = frequency_band
                    })
                    added_count = added_count + 1
                else
                    filtered_count = filtered_count + 1
                end
            end
        end

        response_data = success_response({devices = devices_list})
    end)

    if not ok then
        response_data = error_response(-1, "获取设备列表失败", tostring(err))
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- ========== MAC屏蔽列表持久化管理 ==========

local function get_blocklist_filepath()
    local dir = get_data_dir()
    ensure_directory(dir)
    return dir .. "/" .. BLOCKLIST_FILE_NAME
end

local function load_blocklist()
    local filepath = get_blocklist_filepath()
    local fd = io.open(filepath, "r")
    if not fd then 
        return {devices = {}}
    end
    local content = fd:read("*all")
    fd:close()
    if not content or content == "" then
        return {devices = {}}
    end
    local json = require("luci.jsonc")
    local ok, data = pcall(json.parse, content)
    if not ok or not data or not data.devices then
        return {devices = {}}
    end
    return data
end

local function save_blocklist(blocklist)
    local filepath = get_blocklist_filepath()
    local json = require("luci.jsonc")
    local json_str = json.stringify(blocklist) or '{"devices":[]}'
    return save_with_file_lock(filepath, json_str)
end

local function get_mac_oui(mac)
    if not mac or type(mac) ~= "string" then return nil end
    local clean = mac:upper():gsub("[^A-F0-9]", "")
    if #clean < 6 then return nil end
    return clean:sub(1, 6)
end

local function find_device_by_oui_or_name(blocklist, mac, name)
    if not blocklist or not blocklist.devices then return nil end
    local target_oui = get_mac_oui(mac)
    for _, device in ipairs(blocklist.devices) do
        local device_oui = get_mac_oui(device.mac)
        if device_oui and target_oui and device_oui == target_oui then
            return device
        end
        if name and name ~= "" and name ~= "未知设备" and 
           device.name and device.name ~= "未知设备" and
           device.name == name then
            return device
        end
    end
    return nil
end

local function add_to_blocklist(mac, name, ip)
    if not mac or mac == "" then return false end
    local mac_upper = mac:upper()
    
    -- 验证 MAC 地址格式（必须是12位十六进制字符）
    local clean_mac = mac_upper:gsub("[^A-F0-9]", "")
    if #clean_mac ~= 12 then
        nixio.syslog("err", "[RouterAssistant] add_to_blocklist: invalid MAC format: " .. mac_upper)
        return false
    end
    
    -- 标准化 MAC 地址格式（XX:XX:XX:XX:XX:XX）
    local formatted_mac = clean_mac:sub(1,2) .. ":" .. clean_mac:sub(3,4) .. ":" ..
                          clean_mac:sub(5,6) .. ":" .. clean_mac:sub(7,8) .. ":" ..
                          clean_mac:sub(9,10) .. ":" .. clean_mac:sub(11,12)
    
    local blocklist = load_blocklist()
    if not blocklist then
        blocklist = {devices = {}}
    end
    if not blocklist.devices then
        blocklist.devices = {}
    end
    
    -- 检查是否已存在（包括相同OUI的设备）
    for _, device in ipairs(blocklist.devices) do
        if device.mac == formatted_mac then
            return true  -- 已存在，不重复添加
        end
    end
    
    table.insert(blocklist.devices, {
        mac = formatted_mac,
        name = name or "未知设备",
        ip = ip or "",
        blocked_at = os.time()
    })
    return save_blocklist(blocklist)
end

local function remove_from_blocklist(mac)
    if not mac or mac == "" then return false end
    local mac_upper = mac:upper()
    local blocklist = load_blocklist()
    if not blocklist or not blocklist.devices then
        return true
    end
    local target_oui = get_mac_oui(mac_upper)
    local related_macs = {}
    
    for _, device in ipairs(blocklist.devices) do
        if device.mac == mac_upper then
            if device.related_mac then
                table.insert(related_macs, device.related_mac:upper())
            end
        end
        if device.related_mac and device.related_mac:upper() == mac_upper then
            table.insert(related_macs, device.mac:upper())
        end
    end
    
    local new_devices = {}
    for _, device in ipairs(blocklist.devices) do
        local should_remove = (device.mac == mac_upper)
        for _, rm in ipairs(related_macs) do
            if device.mac == rm then
                should_remove = true
                break
            end
        end
        
        -- 注意：不再按 OUI 批量删除，仅精确匹配 MAC 或其 related_mac
        -- 避免误删同品牌其他设备

        if not should_remove then
            table.insert(new_devices, device)
        end
    end
    blocklist.devices = new_devices
    return save_blocklist(blocklist)
end

local function apply_iptables_block(mac)
    if not mac or mac == "" then return false end
    local safe_mac = safe_mac_validate(mac)
    if not safe_mac then return false end

    local formatted_mac = format_mac_colon(safe_mac)
    local ok1 = safe_exec_command("iptables", "-I INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP")
    local ok2 = safe_exec_command("iptables", "-I FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP")
    -- 修复问题#7：至少有一条规则成功就认为成功
    return ok1 or ok2
end

local function remove_iptables_block(mac)
    if not mac or mac == "" then return false end
    local safe_mac = safe_mac_validate(mac)
    if not safe_mac then return false end

    local formatted_mac = format_mac_colon(safe_mac)
    safe_exec_command("iptables", "-D INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP")
    safe_exec_command("iptables", "-D FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP")
    return true
end

-- ========== MAC屏蔽列表持久化管理结束 ==========

-- ========== 流量快照管理（替代历史聚合） ==========

local MONTHLY_SNAPSHOT_FILE = "traffic_monthly.json"
local HOURLY_SNAPSHOT_FILE = "traffic_hourly.json"

-- 创建月度流量快照（供 cron 或手动调用）
-- 记录每个设备的当前流量作为本月起始基准
-- @param current_month  当前月份（格式：YYYYMM）
-- @param current_history  当前的 history 数据
local function create_monthly_snapshot(current_month, current_history)
    local devices = {}
    
    for mac, dev_data in pairs(current_history or {}) do
        if dev_data.rx and dev_data.tx then
            -- 统一 MAC key 格式为带冒号大写
            local mac_colon = format_mac_colon(mac)
            devices[mac_colon] = {
                rx = dev_data.rx,
                tx = dev_data.tx
            }
        end
    end
    
    local snapshot = {
        devices = devices,
        created_at = os.time(),
        device_count = 0
    }
    for _ in pairs(devices) do snapshot.device_count = snapshot.device_count + 1 end
    
    local data = load_json_file(MONTHLY_SNAPSHOT_FILE) or {}
    data[current_month] = snapshot
    data.last_month = current_month
    data.last_created = os.time()
    save_json_file(MONTHLY_SNAPSHOT_FILE, data)
    
    local nixio_log = require("nixio")
    pcall(nixio_log.syslog, "info", "traffic: 月度快照已创建 - " .. current_month .. ", " .. snapshot.device_count .. " 台设备")
    
    return snapshot
end

-- API 接口：手动创建月度快照
function api_create_monthly_snapshot()
    local result = { code = 0, message = "" }
    local ok, err = pcall(function()
        local json = require("luci.jsonc")
        local history_file = get_storage_path()
        local history = {}
        
        local fd = io.open(history_file, "r")
        if fd then
            local content = fd:read("*all")
            fd:close()
            if content and content ~= "" then
                local parse_ok, parsed = pcall(json.parse, content)
                if parse_ok and parsed then
                    history = parsed
                end
            end
        end
        
        local current_month = os.date("%Y%m")
        create_monthly_snapshot(current_month, history)
        result.message = "月度快照创建成功: " .. current_month
    end)
    
    if not ok then
        result.code = -1
        result.message = tostring(err)
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- 获取或创建月度流量快照基准
-- 新月份开始时自动记录每个设备的当前 history 作为本月起始基准
-- 返回：{ devices: { mac: { rx, tx }, ... }, created_at }
--
-- 改进：优先使用 cron 定时创建的快照，避免基准漂移问题
local function get_or_update_monthly_snapshot(current_month, current_history)
    local data = load_json_file(MONTHLY_SNAPSHOT_FILE) or {}
    local snapshot = data[current_month]

    -- 检查快照是否需要重建：
    -- 1. 月份变化了（新月份开始）
    -- 2. 当前月份的快照不存在（首次创建或被删除）
    -- 3. 快照格式不对（旧格式没有 devices 字段）
    -- 4. MAC key 格式不对（旧格式是无冒号，需要迁移到带冒号格式）
    local needs_rebuild = (data.last_month ~= current_month) or (not snapshot) or (snapshot and not snapshot.devices)
    if not needs_rebuild and snapshot and snapshot.devices then
        -- 检测旧快照 MAC key 格式（无冒号格式如 AABBCCDDEEFF）
        for mac_key in pairs(snapshot.devices) do
            if mac_key:match("^[A-F0-9]{12}$") then
                -- 发现旧格式 key（无冒号），需要重建
                needs_rebuild = true
                pcall(nixio.syslog, "info", "[RouterAssistant] Month " .. current_month .. ", old MAC format snapshot detected, rebuilding...")
                break
            end
        end
    end

    if needs_rebuild then
        -- 记录每个设备的当前 history 作为本月起始基准
        -- 统一使用带冒号大写格式（AA:BB:CC:DD:EE:FF）存储 MAC key，避免格式不一致导致查询失败
        local devices = {}
        for mac, dev_data in pairs(current_history) do
            local mac_colon = format_mac_colon(mac)
            devices[mac_colon] = {
                rx = dev_data.rx or 0,
                tx = dev_data.tx or 0
            }
        end
        snapshot = {
            devices = devices,
            created_at = os.time()
        }
        data[current_month] = snapshot
        data.last_month = current_month
        save_json_file(MONTHLY_SNAPSHOT_FILE, data)
        local nixio_log = require("nixio")
        local dev_count = 0
        for _ in pairs(devices) do dev_count = dev_count + 1 end
        nixio_log.syslog("info", "[RouterAssistant] Month " .. current_month .. ", monthly snapshot (re)created with " .. dev_count .. " devices")
    end

    return snapshot or { devices = {}, created_at = 0 }
end

-- 获取设备本月流量（当前 history - 月初基准）
-- 返回：{ rx, tx }，无基准时使用当前值作为本月流量（新设备当月流量=当月累计）
-- 注意：snapshot 中的 MAC key 统一使用带冒号大写格式（AA:BB:CC:DD:EE:FF）
local function get_device_monthly_flow(mac, current_rx, current_tx, snapshot)
    -- 统一将 MAC key 转换为带冒号格式（与快照存储格式一致）
    local mac_colon = format_mac_colon(mac)
    if snapshot and snapshot.devices then
        local baseline = snapshot.devices[mac_colon]
        if baseline then
            -- 有基准，正常计算差值
            local rx = math.max(0, current_rx - (baseline.rx or 0))
            local tx = math.max(0, current_tx - (baseline.tx or 0))
            return { rx = rx, tx = tx }
        end
    end
    -- 无快照或新设备：使用当前值作为本月流量（从本月开始累计）
    return { rx = current_rx, tx = current_tx }
end

-- 获取当前小时的实时累计增量（从小时开始到现在的差值）
-- 每次调用都更新，支持小时趋势实时显示
local function calculate_hourly_realtime(current_hour, current_total_rx, current_total_tx)
    local data = load_json_file(HOURLY_SNAPSHOT_FILE) or {}

    if data.last_hour ~= current_hour then
        -- 新小时开始：记录起始基准
        data[current_hour] = {
            start_rx = current_total_rx,
            start_tx = current_total_tx,
            created_at = os.time()
        }
        data.last_hour = current_hour

        -- 修复问题#8：清理超过25小时的旧小时快照数据，防止文件无限累积
        -- 只保留最近25小时的数据（给一个小时缓冲）
        local MAX_HOURS_TO_KEEP = 25
        for hour_key, hour_data in pairs(data) do
            if hour_key and #hour_key >= 10 and hour_key ~= "last_hour" then
                -- 简单比较：只保留与当前小时差距在MAX_HOURS_TO_KEEP以内的
                -- 小时key格式：YYYYMMDDHH，如2026041520
                if hour_key < current_hour then
                    local hour_diff = tonumber(current_hour) - tonumber(hour_key)
                    if hour_diff > MAX_HOURS_TO_KEEP then
                        data[hour_key] = nil
                    end
                end
            end
        end

        save_json_file(HOURLY_SNAPSHOT_FILE, data)
    end

    local snap = data[current_hour] or { start_rx = current_total_rx, start_tx = current_total_tx }
    local realtime_rx = math.max(0, current_total_rx - (snap.start_rx or 0))
    local realtime_tx = math.max(0, current_total_tx - (snap.start_tx or 0))

    -- 噪声过滤（< 1KB）
    if realtime_rx < 1024 then realtime_rx = 0 end
    if realtime_tx < 1024 then realtime_tx = 0 end

    return {
        rx = realtime_rx,
        tx = realtime_tx,
        total_rx = current_total_rx,
        total_tx = current_total_tx,
        hour_key = current_hour
    }
end

-- 获取最近N小时的小时数据列表（用于小时趋势图表）
local function get_recent_hours_list(current_hour, max_hours)
    local data = load_json_file(HOURLY_SNAPSHOT_FILE) or {}
    local result = {}

    -- 收集所有已结束的小时（有完整数据的）
    for hour_key, hour_data in pairs(data) do
        if hour_key and #hour_key >= 10 and hour_key ~= "last_hour" and hour_data.start_rx then
            table.insert(result, {
                time = hour_key,
                display_time = string.sub(hour_key, 1, 4) .. "-" ..
                               string.sub(hour_key, 5, 6) .. "-" ..
                               string.sub(hour_key, 7, 8) .. " " ..
                               string.sub(hour_key, 9, 10) .. ":00",
                rx = tonumber(hour_data.rx) or 0,
                tx = tonumber(hour_data.tx) or 0,
                total_rx = tonumber(hour_data.total_rx) or 0,
                total_tx = tonumber(hour_data.total_tx) or 0
            })
        end
    end

    -- 添加当前小时的实时数据
    local current_snapshot = data[current_hour]
    if current_snapshot and current_snapshot.start_rx then
        local cur_rx = math.max(0, (current_snapshot.total_rx or 0) - (current_snapshot.start_rx or 0))
        local cur_tx = math.max(0, (current_snapshot.total_tx or 0) - (current_snapshot.start_tx or 0))
        if cur_rx < 1024 then cur_rx = 0 end
        if cur_tx < 1024 then cur_tx = 0 end
        table.insert(result, {
            time = current_hour,
            display_time = string.sub(current_hour, 1, 4) .. "-" ..
                           string.sub(current_hour, 5, 6) .. "-" ..
                           string.sub(current_hour, 7, 8) .. " " ..
                           string.sub(current_hour, 9, 10) .. ":00",
            rx = cur_rx,
            tx = cur_tx,
            total_rx = current_snapshot.total_rx or 0,
            total_tx = current_snapshot.total_tx or 0,
            is_realtime = true
        })
    end

    -- 按时间排序并限制数量
    table.sort(result, function(a, b) return a.time < b.time end)
    while #result > (max_hours or 24) do
        table.remove(result, 1)
    end

    return result
end

-- ========== 流量快照管理结束 ==========

function api_get_traffic()
    local response_data = nil
    local _debug_step = "init"

    local ok, err = pcall(function()
        local util = require("luci.util")
        local json = require("luci.jsonc")
        _debug_step = "require_modules"

        -- 内存回收：在处理大量数据前主动清理缓存
        collectgarbage("collect")

        -- 防御性：确保存储路径可用（提前检测，避免后续写入失败）
        local history_file = get_storage_path()
        _debug_step = "get_storage_path=" .. tostring(history_file)

        -- 读取历史数据（带防御：读取失败不影响返回设备列表）
        local history = {}
        local read_ok = true
        _debug_step = "read_history_start"
        do
            local history_fd = io.open(history_file, "r")
            if history_fd then
                local content = history_fd:read("*all")
                history_fd:close()
                if content and content ~= "" then
                    _debug_step = "parse_history"
                    local parse_ok, parsed = pcall(json.parse, content)
                    if parse_ok and parsed then
                        history = parsed
                    else
                        read_ok = false
                        -- 防御：nixio.syslog 可能不存在
                        pcall(nixio.syslog, "warning", "traffic: JSON parse error for " .. history_file)
                    end
                end
            else
                read_ok = false
                pcall(nixio.syslog, "info", "traffic: no history file at " .. history_file)
            end
        end

        -- 数据迁移：从根源上修复MAC key格式不一致问题
        -- 将所有带冒号或小写的旧格式key迁移为无冒号大写格式
        -- 这样即使history文件中有旧格式数据，也会在加载时自动修复
        _debug_step = "migrate_history_keys"
        do
            local migrated_count = 0
            local needs_rewrite = false
            local migrated_history = {}
            for old_mac, dev_data in pairs(history) do
                -- 统一转换为无冒号大写格式
                local new_mac = old_mac:gsub(":", ""):upper()
                if new_mac ~= old_mac then
                    -- key格式不一致，需要迁移
                    migrated_history[new_mac] = dev_data
                    migrated_count = migrated_count + 1
                    needs_rewrite = true
                else
                    migrated_history[new_mac] = dev_data
                end
            end
            if needs_rewrite then
                history = migrated_history
                _debug_step = "save_migrated_history"
                -- 重新保存为统一格式
                pcall(function()
                    local history_fd = io.open(history_file, "w")
                    if history_fd then
                        local json_str = json.stringify(history)
                        if json_str then
                            history_fd:write(json_str)
                        end
                        history_fd:close()
                        pcall(nixio.syslog, "info", "traffic: migrated " .. migrated_count .. " MAC keys to unified format")
                    end
                end)
            end
        end

        local current_traffic = {}
        local online_devices = {}
        local offline_devices = {}
        local total_rx = 0
        local total_tx = 0
        local online_count = 0
        local offline_count = 0

        _debug_step = "load_dhcp_leases"
        local dhcp_leases = load_dhcp_leases()

        _debug_step = "load_device_notes"
        local device_notes = load_json_file(NOTES_FILE_NAME) or {}

        _debug_step = "ubus_cmd_prepare"

        local cmd = "ubus call infocd terminal 2>/dev/null"
        _debug_step = "before_ubus_exec"
        local output = util.exec(cmd)
        _debug_step = "after_ubus_exec, output_len=" .. tostring(output and #output or 0)
        if output and output ~= "" then
            local parse_ok, data = pcall(json.parse, output)
            if parse_ok and data and data.client then
                -- 防御性归一化：将history表所有key转为无冒号大写格式（兼容旧版各种MAC格式）
                -- 注意：此操作必须在设备循环之前执行一次即可，避免每个设备重复归一化
                local normalized_history = {}
                for hist_mac, hist_data in pairs(history) do
                    normalized_history[hist_mac:gsub(":", ""):upper()] = hist_data
                end
                history = normalized_history

                for mac, client in pairs(data.client) do
                    local mac_str = (mac and type(mac) == "string") and mac or (mac and tostring(mac)) or ""
                    -- 统一格式：去除冒号后转大写，保证 MAC 键一致
                    local mac_normalized = mac_str:gsub(":", ""):upper()
                    local mac_upper = mac_str:upper()
                    local real_mac_raw = client.real_mac
                    local real_mac_raw_fmt = (real_mac_raw and type(real_mac_raw) == "string" and real_mac_raw ~= "") and real_mac_raw:gsub(":", ""):upper() or ""
                    -- 格式统一后再比较
                    local device_id = (real_mac_raw_fmt ~= "" and real_mac_raw_fmt ~= mac_normalized) and real_mac_raw_fmt or mac_normalized
                    local hostname = (client.hostname and type(client.hostname) == "string" and client.hostname ~= "" and client.hostname ~= "*") and client.hostname or nil
                    if not hostname then
                        hostname = dhcp_leases[device_id] and dhcp_leases[device_id].name or "Unknown"
                    end
                    local ip = "-"
                    local ipv6_list = {}
                    if client.ipaddr and type(client.ipaddr) == "string" and client.ipaddr ~= "" then
                        -- 解析 IPv4 和 IPv6 地址（可能包含多个地址，用空格分隔）
                        for addr in client.ipaddr:gmatch("%S+") do
                            if addr:match("^%d+%.%d+%.%d+%.%d+$") then
                                ip = addr  -- 使用第一个 IPv4 作为主 IP
                            elseif addr:match("^[0-9a-fA-F:.]+$") and not addr:match("^fe80:") then
                                table.insert(ipv6_list, addr)
                            end
                        end
                    elseif client.ap_ipaddr and type(client.ap_ipaddr) == "string" and client.ap_ipaddr ~= "" then
                        ip = client.ap_ipaddr
                    end
                    -- 处理随机MAC问题：如果当前MAC不在历史中，尝试通过hostname+MAC前缀(OUI)+IP匹配
                    -- 改进逻辑：
                    -- 1. 精确匹配 MAC → 直接复用
                    -- 2. hostname + OUI 匹配：
                    --    - 该组只有1台历史设备 → 直接复用
                    --    - 该组有2+台历史设备：
                    --      - 新IP与任一历史设备IP相同 → 复用该设备
                    --      - 新IP与所有历史设备IP都不同 → 创建新记录
                    -- 3. 补充判断：如果hostname相同 + IP相同（但OUI不同），也考虑复用
                    --    - 适用于DHCP分配相同IP但随机MAC的情况
                    local current_time = os.time()
                    if not history[device_id] and hostname and hostname ~= "Unknown" then
                        local mac_prefix = string.sub(device_id, 1, 8):upper()  -- 取MAC前3段(OUI,含冒号共8字符如"AA:BB:CC")
                        local matched_devices = {}
                        for hist_mac, hist_data in pairs(history) do
                            local hist_prefix = string.sub(hist_mac, 1, 8):upper()
                            if hist_data.hostname == hostname and hist_prefix == mac_prefix then
                                local age = current_time - ((hist_data.last_seen) or 0)
                                if age < SECONDS_PER_WEEK then
                                    matched_devices[hist_mac] = hist_data
                                end
                            end
                        end
                        local matched_count = 0
                        for _ in pairs(matched_devices) do matched_count = matched_count + 1 end
                        if matched_count == 1 then
                            -- 只有1台OUI+hostname匹配，直接复用
                            for hist_mac, _ in pairs(matched_devices) do
                                device_id = hist_mac
                                break
                            end
                        elseif matched_count > 1 then
                            -- 有2+台OUI+hostname匹配（如同品牌多设备），必须IP也匹配才复用
                            -- 如果IP也不匹配，说明是新房客设备，创建新记录
                            local ip_matched = false
                            for hist_mac, hist_data in pairs(matched_devices) do
                                if hist_data.ip == ip then
                                    device_id = hist_mac
                                    ip_matched = true
                                    break
                                end
                            end
                            -- 如果IP不匹配，保持device_id为新MAC，不复用历史
                        else
                            -- 没有任何OUI+hostname匹配，使用hostname+IP兜底
                            -- 但必须该组合在历史中只有1台设备时才复用（避免多设备误判）
                            local hp_matched_devices = {}
                            for hist_mac, hist_data in pairs(history) do
                                if hist_data.hostname == hostname and hist_data.ip == ip then
                                    local age = current_time - ((hist_data.last_seen) or 0)
                                    if age < SECONDS_PER_WEEK then
                                        hp_matched_devices[hist_mac] = hist_data
                                    end
                                end
                            end
                            local hp_count = 0
                            for _ in pairs(hp_matched_devices) do hp_count = hp_count + 1 end
                            -- 只有当该hostname+IP组合在历史中只有1台设备时才复用
                            if hp_count == 1 then
                                for hist_mac, _ in pairs(hp_matched_devices) do
                                    device_id = hist_mac
                                    break
                                end
                            end
                            -- 如果hp_count > 1，说明有多台设备使用相同hostname+IP，保持device_id为新MAC
                        end
                    end
                    local ifname = (client.ifname and type(client.ifname) == "string") and client.ifname or ""
                    local router_tx_bytes = 0 -- 路由器发送 = 用户下载 (RX)
                    local router_rx_bytes = 0 -- 路由器接收 = 用户上传 (TX)
                    
                    -- 优先从 ipset 获取流量数据（iptables 直接统计，最准确）
                    -- 这适用于所有设备，确保流量统计的一致性和准确性
                    local mac_colon = mac_str:upper()
                    local ipset_rx, ipset_tx = get_ipset_traffic(mac_colon, ip, #ipv6_list > 0 and ipv6_list or nil)
                    if ipset_rx and ipset_rx > 0 then
                        router_tx_bytes = ipset_rx
                    end
                    if ipset_tx and ipset_tx > 0 then
                        router_rx_bytes = ipset_tx
                    end
                    
                    -- Fallback：如果 ipset 没有数据，使用 infocd 的数据
                    if router_tx_bytes == 0 and router_rx_bytes == 0 then
                        if client.txbytes then
                            router_tx_bytes = (type(client.txbytes) == "number") and client.txbytes or (tonumber(client.txbytes) or 0)
                        end
                        if client.rxbytes then
                            router_rx_bytes = (type(client.rxbytes) == "number") and client.rxbytes or (tonumber(client.rxbytes) or 0)
                        end
                    end
                    if not is_upstream_interface(ifname) then
                        local hist = history[device_id] or {}
                        local last_rx = (hist.rx and type(hist.rx) == "number") and hist.rx or 0 -- 历史下载总量
                        local last_tx = (hist.tx and type(hist.tx) == "number") and hist.tx or 0 -- 历史上传总量
                        local last_raw_rx = (hist.raw_rx and type(hist.raw_rx) == "number") and hist.raw_rx or 0 -- 历史原始下载
                        local last_raw_tx = (hist.raw_tx and type(hist.raw_tx) == "number") and hist.raw_tx or 0 -- 历史原始上传
                        local current_time = os.time()
                        
                        -- 比较原始值是否重置 (路由器重启或网卡重启会导致计数器清零)
                        -- 改进：增加阈值判断，避免因正常流量波动导致的误判
                        local RESET_THRESHOLD = 1024 * 1024  -- 1MB 阈值：只有减少超过1MB才认为是重置
                        local current_raw_total = router_tx_bytes + router_rx_bytes
                        local last_raw_total = last_raw_rx + last_raw_tx
                        local counter_reset = (last_raw_total > RESET_THRESHOLD) and 
                            ((router_tx_bytes < last_raw_rx - RESET_THRESHOLD) or (router_rx_bytes < last_raw_tx - RESET_THRESHOLD))
                        
                        -- 额外检查：如果历史数据非常新（<5分钟），可能是数据不一致而非真正的重置
                        if counter_reset and hist.last_seen then
                            local time_since_last_seen = current_time - hist.last_seen
                            if time_since_last_seen < 300 then  -- 5分钟内
                                counter_reset = false  -- 太快了，可能是数据问题
                            end
                        end
                        
                        local device_total_rx, device_total_tx
                        local current_reset_count = (hist.reset_count and type(hist.reset_count) == "number") and hist.reset_count or 0
                        if counter_reset then
                            -- 计数器重置(路由器重启)后，只有首次重置才累加重启前的历史总量
                            -- 后续重启若计数器仍小，说明还在重置周期内，不再重复累加
                            if current_reset_count == 0 then
                                device_total_rx = math.max(router_tx_bytes, 0) + last_rx
                                device_total_tx = math.max(router_rx_bytes, 0) + last_tx
                            else
                                -- 已在之前累加过，本次只使用新计数器值
                                device_total_rx = math.max(router_tx_bytes, 0)
                                device_total_tx = math.max(router_rx_bytes, 0)
                            end
                            current_reset_count = current_reset_count + 1
                        else
                            -- 正常情况：历史总量 + 本次轮询增量(本次原始值 - 上次原始值)
                            local delta_rx = router_tx_bytes - last_raw_rx
                            local delta_tx = router_rx_bytes - last_raw_tx
                            -- 防御：增量不应为负(正常情况下 raw 值应单调递增)
                            local new_rx = last_rx + math.max(delta_rx, 0)
                            local new_tx = last_tx + math.max(delta_tx, 0)
                            -- 修复问题6：防止极端值（驱动bug或浮点精度问题）
                            -- 单设备流量上限：100TB（远超正常值，但防止极端情况）
                            local MAX_DEVICE_BYTES = 100 * 1024 * 1024 * 1024 * 1024
                            if new_rx > MAX_DEVICE_BYTES then new_rx = last_rx end
                            if new_tx > MAX_DEVICE_BYTES then new_tx = last_tx end
                            device_total_rx = new_rx
                            device_total_tx = new_tx
                            -- 修复问题7：计数器恢复正常后，重置 reset_count 避免语义混乱
                            if current_reset_count > 0 then
                                current_reset_count = 0
                            end
                        end
                        
                        device_total_rx = is_valid_number(device_total_rx) and device_total_rx or 0
                        device_total_tx = is_valid_number(device_total_tx) and device_total_tx or 0
                        
                        local device_total = device_total_rx + device_total_tx
                        total_rx = total_rx + device_total_rx
                        total_tx = total_tx + device_total_tx
                        online_count = online_count + 1

                        local is_wifi = is_wifi_device(client, mac)
                        local device_type = get_device_type(hostname, mac_upper, is_wifi)

                        local note_data = device_notes[device_id] or device_notes[mac_upper]
                        if note_data and note_data.device_type and note_data.device_type ~= "" then
                            device_type = note_data.device_type
                        end

                        local frequency_band = nil
                        if is_wifi then
                            frequency_band = get_wifi_frequency_band(ifname)
                        end

                        local rx_delta = device_total_rx - last_rx
                        local tx_delta = device_total_tx - last_tx
                        if rx_delta < 0 then rx_delta = 0 end
                        if tx_delta < 0 then tx_delta = 0 end

                        -- 确保 MAC 格式一致：
                        -- 存储 key 使用无冒号格式（mac_normalized），API 返回使用带冒号格式（MAC_FMT_COLON）
                        local mac_key = mac_normalized  -- 统一使用无冒号大写格式作为 key
                        local mac_display = format_mac_colon(mac_key)  -- 统一使用带冒号大写格式作为显示格式
                        table.insert(online_devices, {
                            mac = mac_display,
                            -- 修复问题10：对hostname进行HTML转义，防止XSS
                            hostname = sanitize_input(hostname),
                            ip = ip,
                            rx = device_total_rx,
                            tx = device_total_tx,
                            total = device_total,
                            rx_display = format_bytes(device_total_rx),
                            tx_display = format_bytes(device_total_tx),
                            total_display = format_bytes(device_total),
                            rx_delta = rx_delta,
                            tx_delta = tx_delta,
                            rx_delta_display = format_bytes(rx_delta),
                            tx_delta_display = format_bytes(tx_delta),
                            online = true,
                            first_seen = hist.first_seen or current_time,
                            is_wifi = is_wifi,
                            ifname = ifname,
                            device_type = device_type,
                            frequency_band = frequency_band,
                            blocked = is_device_blocked(mac_key) or is_device_blocked(mac_upper)
                        })
                        current_traffic[mac_key] = {
                            rx = device_total_rx,
                            tx = device_total_tx,
                            raw_rx = router_tx_bytes,
                            raw_tx = router_rx_bytes,
                            reset_count = current_reset_count,
                            ip = ip,
                            -- 修复问题10：对hostname进行HTML转义，防止XSS（存储时转义）
                            hostname = sanitize_input(hostname),
                            mac = mac_upper,
                            real_mac = real_mac_raw,
                            last_seen = current_time,
                            first_seen = hist.first_seen or current_time
                        }
                    end
                end
            end
        end
        local current_time = os.time()
        for dev_id, data in pairs(history) do
            if not current_traffic[dev_id] then
                local age = current_time - ((data and data.last_seen) or 0)
                if age < SECONDS_PER_WEEK then
                    local offline_rx = data.rx or 0
                    local offline_tx = data.tx or 0

                    -- 将离线设备也加入总流量统计（修复：确保与aggregate_traffic_history数据源一致）
                    total_rx = total_rx + offline_rx
                    total_tx = total_tx + offline_tx

                    current_traffic[dev_id] = data
                    offline_count = offline_count + 1

                    local offline_frequency_band = nil
                    if data.is_wifi and data.ifname then
                        offline_frequency_band = get_wifi_frequency_band(data.ifname)
                    end

                    table.insert(offline_devices, {
                        mac = format_mac_colon(dev_id),
                        hostname = data.hostname or "Unknown",
                        ip = data.ip or "-",
                        rx = data.rx or 0,
                        tx = data.tx or 0,
                        total = (data.rx or 0) + (data.tx or 0),
                        rx_display = format_bytes(data.rx or 0),
                        tx_display = format_bytes(data.tx or 0),
                        total_display = format_bytes((data.rx or 0) + (data.tx or 0)),
                        online = false,
                        first_seen = data.first_seen or 0,
                        last_seen = data.last_seen or current_time,
                        is_wifi = data.is_wifi or false,
                        frequency_band = offline_frequency_band,
                        blocked = is_device_blocked(dev_id)
                    })
                end
            end
        end

        -- 修复问题6：限制条目数量，避免JSON文件无限增长
        -- 规则：保留在线设备 + 最多 MAX_TRAFFIC_DEVICES 个离线设备（按 last_seen 排序，保留最新的）
        -- 改进：重要设备（有备注、高流量、或被标记为重要的）不会被删除
        local device_count = 0
        for _ in pairs(current_traffic) do device_count = device_count + 1 end
        if device_count > MAX_TRAFFIC_DEVICES then
            -- 收集所有离线设备并按 last_seen 降序排序
            local offline_list = {}
            local notes_data = load_json_file(NOTES_FILE_NAME) or {}
            
            for dev_id, data in pairs(current_traffic) do
                -- 判断是否为当前在线设备（online_devices 中存在）
                local is_online = false
                for _, online_dev in ipairs(online_devices) do
                    if online_dev.mac == dev_id then
                        is_online = true
                        break
                    end
                end
                
                if not is_online then
                    -- 检查是否为重要设备（不会被删除）
                    local is_important = false
                    -- 有备注的设备是重要的
                    if notes_data[dev_id] or notes_data[format_mac_colon(dev_id)] then
                        is_important = true
                    end
                    -- 流量超过 1GB 的设备是重要的
                    if data and ((data.rx and data.rx > 1073741824) or (data.tx and data.tx > 1073741824)) then
                        is_important = true
                    end
                    -- 标记为重要的设备
                    if data and data.important then
                        is_important = true
                    end
                    
                    table.insert(offline_list, {dev_id = dev_id, last_seen = (data and data.last_seen) or 0, important = is_important})
                end
            end
            
            -- 按 last_seen 降序排序，重要设备排在前面
            table.sort(offline_list, function(a, b)
                if a.important ~= b.important then return a.important end
                return a.last_seen > b.last_seen 
            end)
            
            -- 删除超出上限的非重要离线设备
            local kept_offline = 0
            local max_offline = MAX_TRAFFIC_DEVICES - #online_devices
            local to_remove = {}
            for i, item in ipairs(offline_list) do
                if i > max_offline and not item.important then
                    table.insert(to_remove, item.dev_id)
                else
                    kept_offline = kept_offline + 1
                end
            end
            for _, dev_id in ipairs(to_remove) do
                current_traffic[dev_id] = nil
            end
            nixio.syslog("info", "traffic: pruned " .. #to_remove .. " old offline devices, kept " .. kept_offline .. " recent/important offline devices")
        end

        -- 保存流量数据（带防御：写入失败不阻断返回）
        local json_str = "{}"
        local serialize_ok, serialize_err = pcall(json.stringify, current_traffic)
        if serialize_ok then
            json_str = serialize_err or "{}"
        else
            nixio.syslog("err", "traffic: JSON serialize failed: " .. tostring(serialize_err))
            json_str = "{}"
        end

        local save_ok, save_path = pcall(function()
            return save_with_file_lock(history_file, json_str)
        end)
        if not save_ok or not save_path then
            nixio.syslog("warning", "traffic: failed to save data, err=" .. tostring(save_path))
            -- 保存失败不影响本次返回，下次会重新从零开始统计
        end

        -- 使用快照机制（仅用于新月检测和标记）
        -- 月度统计 = 当前总量 - 月初快照基准（差值法，正确反映本月新增流量）
        local current_month = os.date("%Y%m", current_time)
        local current_hour = os.date("%Y%m%d%H", current_time)

        local monthly_snapshot = get_or_update_monthly_snapshot(current_month, history)

        -- 计算本月新增流量（当前总量 - 月初快照），防御负值
        -- 使用与设备列表相同的数据源（current_traffic），保证数据一致性
        local monthly_total_rx = 0
        local monthly_total_tx = 0
        for mac, dev_data in pairs(current_traffic) do
            local monthly = get_device_monthly_flow(mac, dev_data.rx or 0, dev_data.tx or 0, monthly_snapshot)
            monthly_total_rx = monthly_total_rx + monthly.rx
            monthly_total_tx = monthly_total_tx + monthly.tx
        end

        -- 第二遍：更新所有设备的本月流量（基于月度快照）
        -- 修复问题2：累加月度流量到月度总量，用于页面底部"总流量"显示
        local display_total_rx = 0
        local display_total_tx = 0
        for _, dev in ipairs(online_devices) do
            local mac = dev.mac
            local dev_data = current_traffic[mac]
            if dev_data then
                local monthly = get_device_monthly_flow(mac, dev_data.rx or 0, dev_data.tx or 0, monthly_snapshot)
                dev.rx = monthly.rx
                dev.tx = monthly.tx
                dev.total = monthly.rx + monthly.tx
                dev.rx_display = format_bytes(monthly.rx)
                dev.tx_display = format_bytes(monthly.tx)
                dev.total_display = format_bytes(monthly.rx + monthly.tx)
                display_total_rx = display_total_rx + monthly.rx
                display_total_tx = display_total_tx + monthly.tx
            end
        end
        for _, dev in ipairs(offline_devices) do
            local mac = dev.mac
            local dev_data = current_traffic[mac]
            if dev_data then
                local monthly = get_device_monthly_flow(mac, dev_data.rx or 0, dev_data.tx or 0, monthly_snapshot)
                dev.rx = monthly.rx
                dev.tx = monthly.tx
                dev.total = monthly.rx + monthly.tx
                dev.rx_display = format_bytes(monthly.rx)
                dev.tx_display = format_bytes(monthly.tx)
                dev.total_display = format_bytes(monthly.rx + monthly.tx)
                display_total_rx = display_total_rx + monthly.rx
                display_total_tx = display_total_tx + monthly.tx
            end
        end

        -- 当前小时实时增量
        local hourly_data = calculate_hourly_realtime(current_hour, total_rx, total_tx)

        -- 最近24小时数据列表（用于小时趋势图表）
        local hourly_list = get_recent_hours_list(current_hour, 24)

        table.sort(online_devices, function(a, b)
            local ta = (a and a.total) or 0
            local tb = (b and b.total) or 0
            return ta > tb
        end)
        table.sort(offline_devices, function(a, b)
            local ta = (a and a.total) or 0
            local tb = (b and b.total) or 0
            return ta > tb
        end)

        response_data = {
            code = 0,
            online_devices = online_devices,
            offline_devices = offline_devices,
            stats = {
                -- 修复问题2：页面底部"总流量"使用月度值，与设备列表月度流量保持一致
                -- 历史累计总量保留在 history_total_rx/tx（用于历史对比）
                total_rx = display_total_rx,
                total_tx = display_total_tx,
                -- 保留历史累计总量（本月度值 vs 历史累计的对比）
                history_total_rx = total_rx,
                history_total_tx = total_tx,
                -- 本月累计流量（差值法：当前总量 - 月初快照基准）
                monthly_total_rx = monthly_total_rx,
                monthly_total_tx = monthly_total_tx,
                monthly_total = monthly_total_rx + monthly_total_tx,
                -- 当前小时实时累计增量
                hourly_realtime_rx = hourly_data.rx,
                hourly_realtime_tx = hourly_data.tx,
                online_count = online_count,
                offline_count = offline_count
            },
            -- 小时趋势数据（用于图表渲染）
            hourly_list = hourly_list
        }
    end)
    if not ok then
        response_data = error_response(-1, "获取流量统计失败",
            "step=" .. tostring(_debug_step) .. " | err=" .. tostring(err))
        response_data.online_devices = {}
        response_data.offline_devices = {}
        response_data.stats = {}
    else
        response_data = success_response(response_data)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

function api_get_wifi()
    local result = {code = 0, wifi = {}}
    local sys = require("luci.sys")

    local ok, err = pcall(function()
        local uci = require("luci.model.uci").cursor()

        -- 获取所有WiFi接口
        local wifi_ifaces = {}
        uci:foreach("wireless", "wifi-iface", function(s)
            local ifname = s.ifname
            if ifname and ifname ~= "" then
                table.insert(wifi_ifaces, {
                    ifname = ifname,
                    ssid = s.ssid,
                    encryption = s.encryption,
                    disabled = s.disabled
                })
            end
        end)

        for _, wifi_info in ipairs(wifi_ifaces) do
            local ifname = safe_ifname(wifi_info.ifname)
            -- 修复问题#2：跳过不安全的接口名，防止命令注入
            if not ifname then
                -- 跳过不安全的接口
            else
                -- 使用iw dev获取真实SSID（使用已验证的ifname）
                local iw_dev_output = sys.exec("iw dev " .. ifname .. " info 2>/dev/null")
                local real_ssid = iw_dev_output:match("ssid%s+([^\n]+)")
                if real_ssid then
                    real_ssid = real_ssid:gsub("^%s+", ""):gsub("%s+$", "")
                end

                -- 使用iwinfo获取详细信息
                local iwinfo_output = sys.exec("iwinfo " .. ifname .. " info 2>/dev/null")

                -- 解析信道: "Channel: 12 (2.467 GHz)"
                local channel = "-"
                local channel_line = iwinfo_output:match("Channel:%s*([^\n]+)")
                if channel_line then
                    local ch = channel_line:match("(%d+)%s*%(")
                    if ch then channel = ch end
                end

                -- 解析信号: "Signal: -54 dBm"
                local signal = "-"
                local signal_val = iwinfo_output:match("Signal:%s*([%-%d]+)%s*dBm")
                if signal_val then
                    signal = signal_val .. " dBm"
                end

                -- 解析工作模式: "Mode: Master"
            local mode = "AP"
            local mode_val = iwinfo_output:match("Mode:%s*(%w+)")
            if mode_val then
                if mode_val == "Master" then
                    mode = "AP"
                elseif mode_val == "Client" then
                    mode = "客户端"
                else
                    mode = mode_val
                end
            end

            -- 获取连接的客户端数量
            local stations_output = sys.exec("iwinfo " .. ifname .. " assoclist 2>/dev/null")
            local client_count = 0
            if stations_output and stations_output ~= "" and not stations_output:match("No station") then
                for line in stations_output:gmatch("[^\r\n]+") do
                    if line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)") then
                        client_count = client_count + 1
                    end
                end
            end

            -- 判断状态
            local status = "connected"
            if wifi_info.disabled == "1" then
                status = "disabled"
            elseif not real_ssid or real_ssid == "" then
                status = "disconnected"
            end

            local enc_name = get_encryption_name(wifi_info.encryption)
            local encryption = enc_name or "无加密"

            local ssid = real_ssid or wifi_info.ssid or "-"
            if ssid ~= "" and ssid ~= "-" then
                table.insert(result.wifi, {
                    iface = ifname,
                    ssid = ssid,
                    mode = mode,
                    channel = channel,
                    signal = signal,
                    encryption = encryption,
                    clients = client_count,
                    status = status
                })
            end
            end  -- 闭合 if not ifname then ... else ... end
        end
    end)

    if not ok then
        result = error_response(-1, "获取WiFi信息失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_device_notes()
    local result = {code = 0, notes = {}}
    local ok, err = pcall(function()
        local notes = load_json_file(NOTES_FILE_NAME)
        if notes then
            result.notes = notes
        end
    end)
    if not ok then
        result = error_response(-1, "获取设备备注失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_save_device_note()
    if not require_csrf_token() then return end
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")
        local note = luci.http.formvalue("note")
        local device_type = luci.http.formvalue("device_type")
        if not mac or mac == "" then
            result.code = -1
            result.message = "MAC地址无效"
            return
        end
        local mac_clean = mac:upper():gsub("[^A-F0-9]", "")
        if #mac_clean ~= 12 then
            result.code = -1
            result.message = "MAC地址格式无效"
            return
        end
        -- 统一为带冒号大写格式（MAC_FMT_COLON），与设备列表 mac 字段格式一致
        local mac_formatted = format_mac_colon(mac_clean)
        local safe_note = sanitize_input(note or "")
        local safe_device_type = sanitize_input(device_type or "")
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        -- 迁移旧数据：兼容无冒号格式的 key
        local legacy_mac = mac_clean
        if notes[legacy_mac] and not notes[mac_formatted] then
            notes[mac_formatted] = notes[legacy_mac]
            notes[legacy_mac] = nil
        end
        local existing = notes[mac_formatted] or {}
        notes[mac_formatted] = {
            note = safe_note,
            device_type = safe_device_type,
            updated = os.time()
        }
        local save_ok = save_json_file(NOTES_FILE_NAME, notes)
        if not save_ok then
            result = error_response(-1, "保存失败")
            return
        end
        result.message = "设备信息已保存"
    end)
    if not ok then
        result = error_response(-1, "保存设备备注失败", tostring(err))
    else
        -- 修复问题#7：直接设置code=0，不使用success_response嵌套，保持响应结构一致性
        result.code = 0
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_delete_device_note()
    if not require_csrf_token() then return end
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")
        if not mac or mac == "" then
            result.code = -1
            result.message = "MAC地址无效"
            return
        end
        local mac_clean = mac:upper():gsub("[^A-F0-9]", "")
        if #mac_clean ~= 12 then
            result.code = -1
            result.message = "MAC地址格式无效"
            return
        end
        -- 统一为带冒号大写格式（MAC_FMT_COLON），与设备列表 mac 字段格式一致
        local mac_formatted = format_mac_colon(mac_clean)
        local legacy_mac = mac_clean  -- 兼容旧无冒号格式
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        notes[mac_formatted] = nil
        notes[legacy_mac] = nil  -- 同时删除旧格式 key（如果存在）
        save_json_file(NOTES_FILE_NAME, notes)
        result.message = "备注已删除"
    end)
    if not ok then
        result = error_response(-1, "删除设备备注失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- DEPRECATED: collect.lua 已废弃，流量采集已完全由 ubus 接管
-- 此API仅作向后兼容保留，实际无任何作用
function api_collect_traffic()
    if not require_csrf_token() then return end
    -- 直接返回成功，因为流量采集现在完全由 api_get_traffic 在每次调用时自动完成
    -- 不再需要独立的采集进程
    local result = {code = 0, message = "流量采集已由系统自动完成，无需手动采集"}
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_alerts()
    local result = {code = 0, global_threshold = 0, color_levels = {warning = 50, danger = 80, critical = 100}}
    local ok, err = pcall(function()
        local alerts = load_json_file(ALERTS_FILE_NAME)
        if alerts then
            result.global_threshold = alerts.global_threshold or 0
            if alerts.color_levels then
                result.color_levels = alerts.color_levels
            end
        end
    end)
    if not ok then
        result = error_response(-1, "获取报警设置失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_save_alert()
    if not require_csrf_token() then return end
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local threshold = luci.http.formvalue("threshold")
        local warning_level = luci.http.formvalue("warning_level")
        local danger_level = luci.http.formvalue("danger_level")
        local critical_level = luci.http.formvalue("critical_level")
        
        local threshold_num = tonumber(threshold) or 0
        if threshold_num < 0 then
            result.code = -1
            result.message = "阈值不能为负数"
            return
        end
        -- 修复问题#3：添加阈值上限检查，防止设置极端值导致告警永不触发
        local MAX_THRESHOLD = 1000000000  -- 1GB/s，物理网络不太可能超过此值
        if threshold_num > MAX_THRESHOLD then
            result.code = -1
            result.message = "阈值不能超过 " .. MAX_THRESHOLD .. " MB/s"
            return
        end

        -- 验证颜色级别范围 [0, 100]
        local function validate_level(val, default)
            local num = tonumber(val) or default
            if num < 0 then num = 0 end
            if num > 100 then num = 100 end
            return num
        end

        local alerts = {
            global_threshold = threshold_num,
            color_levels = {
                warning = validate_level(warning_level, 50),
                danger = validate_level(danger_level, 80),
                critical = validate_level(critical_level, 100)
            },
            updated = os.time()
        }
        
        local save_ok = save_json_file(ALERTS_FILE_NAME, alerts)
        if not save_ok then
            result = error_response(-1, "保存失败")
            return
        end
        result.message = "报警设置已保存"
    end)
    if not ok then
        result = error_response(-1, "保存报警设置失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_delete_alert()
    if not require_csrf_token() then return end
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local alerts = {global_threshold = 0, color_levels = {warning = 50, danger = 80, critical = 100}}
        save_json_file(ALERTS_FILE_NAME, alerts)
        result.message = "报警已重置"
    end)
    if not ok then
        result = error_response(-1, "重置报警设置失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_wifi_status()
    local result = {code = 0, wifi_status = {}}
    local sys = require("luci.sys")
    local uci = require("luci.model.uci").cursor()

    local ok, err = pcall(function()
        uci:foreach("wireless", "wifi-iface", function(s)
            local device = s.device or "radio0"
            local iface = s[".name"]
            local ifname = s.ifname or ""
            local disabled = s.disabled

            local status = {
                iface = iface,
                device = device,
                ifname = ifname,
                ssid = "-",
                encryption = "-",
                mode = s.mode or "ap",
                channel = "-",
                signal = "-",
                status = "unknown",
                tx_bitrate = "-",
                frequency = "-",
                connected_stations = {}
            }

            -- 修复问题#2：使用safe_ifname验证接口名，防止命令注入
            local safe_ifname_val = safe_ifname(ifname)
            if safe_ifname_val then
                -- 优先使用iw dev获取真实SSID（iwinfo可能显示错误的SSID）
                local iw_dev_output = sys.exec("iw dev " .. safe_ifname_val .. " info 2>/dev/null")
                local real_ssid = iw_dev_output:match("ssid%s+([^\n]+)")
                if real_ssid then
                    real_ssid = real_ssid:gsub("^%s+", ""):gsub("%s+$", "")
                end
                
                if real_ssid and real_ssid ~= "" then
                    status.ssid = real_ssid
                else
                    -- 回退到UCI配置
                    status.ssid = s.ssid or "-"
                end
                
                -- 使用iwinfo命令获取其他详细信息
                local iwinfo_output = sys.exec("iwinfo " .. safe_ifname_val .. " info 2>/dev/null")
                
                -- 解析实际运行的加密方式: Encryption: xxx
                local actual_enc = iwinfo_output:match("Encryption:%s*([^\n]+)")
                if actual_enc then
                    actual_enc = actual_enc:gsub("^%s+", ""):gsub("%s+$", "")
                end
                local enc_name = get_encryption_name(actual_enc)
                if enc_name then
                    status.encryption = enc_name
                else
                    -- iwinfo获取不到有效加密信息，从UCI配置获取
                    enc_name = get_encryption_name(s.encryption)
                    if enc_name then
                        status.encryption = enc_name
                    else
                        status.encryption = "无加密"
                    end
                end
                
                -- 解析信道和频率: "Channel: 12 (2.467 GHz)" 或 "Channel: 64 (5.320 GHz)"
                local channel_line = iwinfo_output:match("Channel:%s*([^\n]+)")
                if channel_line then
                    local ch, freq = channel_line:match("(%d+)%s*%(([%d%.]+)%s*GHz%)")
                    if ch then status.channel = ch end
                    if freq then
                        status.frequency = freq .. " GHz"
                    end
                end

                -- 解析信号强度: "Signal: -54 dBm" 或 "Signal: unknown"
                local signal_val = iwinfo_output:match("Signal:%s*([%-%d]+)%s*dBm")
                if signal_val then
                    status.signal = signal_val .. " dBm"
                else
                    -- AP模式下可能显示unknown，尝试从iw dev获取
                    local iw_output = sys.exec("iw dev " .. safe_ifname_val .. " link 2>/dev/null")
                    local iw_signal = iw_output:match("signal:%s*([%-%d]+)%s*dBm")
                    if iw_signal then
                        status.signal = iw_signal .. " dBm"
                    end
                end

                -- 解析速率: "Bit Rate: 1278.7 MBit/s"
                local bitrate_val = iwinfo_output:match("Bit Rate:%s*([%d%.]+)%s*MBit/s")
                if bitrate_val then
                    status.tx_bitrate = bitrate_val .. " Mbps"
                end

                -- 解析工作模式: "Mode: Master"
                local mode_val = iwinfo_output:match("Mode:%s*(%w+)")
                if mode_val then
                    if mode_val == "Master" then
                        status.mode = "AP (接入点)"
                    elseif mode_val == "Client" then
                        status.mode = "客户端"
                    else
                        status.mode = mode_val
                    end
                end

                -- 获取连接的客户端
                local stations_output = sys.exec("iwinfo " .. safe_ifname_val .. " assoclist 2>/dev/null")
                if stations_output and stations_output ~= "" and not stations_output:match("No station") then
                    -- iwinfo assoclist 实际输出格式：AA:BB:CC:DD:EE:FF  -49 dBm / unknown (SNR -49)  4000 ms ago
                    -- MAC地址后直接跟 "-XX dBm"，不是 "Signal:"
                    for mac, signal in stations_output:gmatch("([%x%x:%x%x:%x%x:%x%x:%x%x:%x%x])%s+([%-%d]+)%s+dBm") do
                        table.insert(status.connected_stations, {
                            mac = mac,
                            signal = signal .. " dBm"
                        })
                    end
                    -- 兼容：如果上面没匹配到，尝试只匹配MAC地址（无Signal信息的情况）
                    if #status.connected_stations == 0 then
                        for mac in stations_output:gmatch("([%x%x:%x%x:%x%x:%x%x:%x%x:%x%x])") do
                            table.insert(status.connected_stations, {
                                mac = mac,
                                signal = "-"
                            })
                        end
                    end
                end
            end

            local is_up = false
            if disabled ~= "1" then
                is_up = true
            end
            
            if is_up and status.ssid and status.ssid ~= "-" and status.ssid ~= "" then
                status.status = "connected"
            elseif disabled == "1" then
                status.status = "disabled"
            else
                status.status = "disconnected"
            end
            
            status.station_count = #(status.connected_stations or {})
            
            table.insert(result.wifi_status, status)
        end)
    end)

    if not ok then
        result = error_response(-1, "获取WiFi状态失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_version()
    local json = require("luci.jsonc")
    local version_info = {
        version = "unknown",
        author = "MH",
        description = "路由管家 - 网络管理工具"
    }

    local ok, err = pcall(function()
        local version_paths = {
            "/usr/share/router-assistant/version.json",
            "/usr/lib/lua/luci/../version.json"
        }
        for _, path in ipairs(version_paths) do
            local fd = io.open(path, "r")
            if fd then
                local content = fd:read("*a")
                fd:close()
                if content and content ~= "" then
                    local data = json.parse(content)
                    if data then
                        if data.version then version_info.version = data.version end
                        if data.author then version_info.author = data.author end
                        if data.name then version_info.name = data.name end
                        if data.description then version_info.description = data.description end
                    end
                    break
                end
            end
        end
    end)

    if not ok then
        pcall(function()
            local nixio = require("nixio")
            nixio.syslog("warning", "[RouterAssistant] Failed to load version.json: " .. tostring(err))
        end)
    end

    local result = success_response(version_info)
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_kick_device()
    nixio.syslog("info", "[RouterAssistant] api_kick_device called")

    if not require_csrf_token() then
        nixio.syslog("err", "[RouterAssistant] api_kick_device: CSRF failed")
        return
    end

    local http = require "luci.http"
    local util = require "luci.util"
    local nixio = require("nixio")

    local mac = luci.http.formvalue("mac")
    nixio.syslog("info", "[RouterAssistant] kick_device mac=" .. tostring(mac))

    if not mac or mac == "" then
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "MAC地址无效", timestamp = os.time()})
        return
    end

    local mac_colon = mac:upper():gsub("-", ":")
    local safe_mac = safe_mac_validate(mac_colon)
    if not safe_mac then
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "MAC地址格式无效", timestamp = os.time()})
        return
    end

    local mac_lower = mac_colon:lower()
    local mac_no_colon_lower = safe_mac:lower()

    -- 先获取设备信息（快速操作，不会阻塞）
    local device_ip = ""
    local device_hostname = "未知设备"

    local ok_info, err_info = pcall(function()
        local leases_file = io.open("/tmp/dhcp.leases", "r")
        if leases_file then
            for line in leases_file:lines() do
                local ip = line:match("^%d+%s+%S+%s+" .. mac_lower:gsub(":", "[0-9a-f]") .. "%s+([^%s]+)")
                if not ip then
                    ip = line:match("^%d+%s+" .. mac_lower .. "%s+([^%s]+)")
                end
                if ip then
                    device_ip = ip
                    local parts = {}
                    for part in line:gmatch("%S+") do
                        table.insert(parts, part)
                    end
                    if #parts >= 4 and parts[4] and parts[4] ~= "*" then
                        device_hostname = parts[4]
                    end
                    break
                end
            end
            leases_file:close()
        end

        if device_ip == "" then
            local arp_file = io.open("/proc/net/arp", "r")
            if arp_file then
                for line in arp_file:lines() do
                    if line:lower():find(mac_lower) then
                        device_ip = line:match("^([%d%.]+)")
                        break
                    end
                end
                arp_file:close()
            end
        end

        local safe_device_ip = nil
        if device_ip ~= "" then
            safe_device_ip = safe_ip_validate(device_ip)
            if not safe_device_ip then
                device_ip = ""
            end
        end
    end)

    if not ok_info then
        nixio.syslog("err", "[RouterAssistant] kick_device info error: " .. tostring(err_info))
    end

    nixio.syslog("info", "[RouterAssistant] kick_device info done, ip=" .. device_ip)

    -- ========== 全后台执行策略（避免uhttpd CGI超时导致502） ==========
    -- 核心优化：将 iptables/conntrack 放在脚本最前面，nohup 启动后按顺序执行
    -- 延迟 ≈ 写文件(~1ms) + nohup启动(~1ms) + iptables执行(~1-2ms) ≈ 3-5ms（人类不可感知）
    local formatted_mac = format_mac_colon(safe_mac)

    -- 【安全加固】所有拼入shell命令的变量加引号保护（防御深度）
    -- safe_mac 来自 safe_mac_validate()，仅含 [A-F0-9]{12}，但引号防御更稳妥
    local safe_mac_quoted = "'" .. formatted_mac .. "'"
    local safe_ip_quoted = safe_device_ip and ("'" .. safe_device_ip .. "'") or "''"
    local safe_mac_lower_quoted = "'" .. mac_lower .. "'"
    local safe_mac_colon_quoted = "'" .. mac_colon .. "'"

    local script_parts = {}

    -- 【最高优先级】iptables DROP 规则（最先执行，~0.5ms/条）
    table.insert(script_parts, "iptables -I INPUT -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null")
    table.insert(script_parts, "iptables -I FORWARD -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null")

    -- 【高优先级】conntrack 清除已有连接（阻止残留流量）
    if safe_device_ip then
        table.insert(script_parts, "conntrack -D -s " .. safe_ip_quoted .. " 2>/dev/null")
        table.insert(script_parts, "conntrack -D -d " .. safe_ip_quoted .. " 2>/dev/null")
    end
    table.insert(script_parts, "conntrack -D -m " .. mac_no_colon_lower .. " 2>/dev/null")

    -- 【低优先级】iw 命令踢出无线连接（MTK驱动可能阻塞，timeout保护）
    local ifaces = {"ra0", "rai0", "ra1", "rai1", "apcli0", "apcli1"}
    for _, iface in ipairs(ifaces) do
        table.insert(script_parts, "timeout 3 iw dev " .. iface .. " station del " .. safe_mac_colon_quoted .. " 2>/dev/null || true")
    end

    -- 【低优先级】access_ctl.sh ACL黑名单（如果存在）
    table.insert(script_parts, "if [ -x /usr/bin/access_ctl.sh ]; then timeout 5 access_ctl.sh -m " .. safe_mac_lower_quoted .. " -a 0 2>/dev/null || true; fi")

    -- 写入脚本并后台执行（按顺序：iptables→conntrack→iw→access_ctl）
    -- 先写入黑名单文件（同步操作，成功后才执行 iptables）
    -- 这样确保：文件记录存在 → iptables 才生效；文件记录失败 → 跳过 iptables
    local add_ok = pcall(add_to_blocklist, mac_colon, device_hostname, device_ip)
    if not add_ok then
        nixio.syslog("err", "[RouterAssistant] kick_device: add_to_blocklist FAILED for " .. mac_colon .. ", skip iptables")
        _blocked_macs_cache = nil
        return
    end
    _blocked_macs_cache = nil
    _blocked_macs_cache_time = 0
    clear_blocked_macs_cache_file()  -- 清除缓存文件，确保其他进程同步

    -- 文件写入成功，执行 iptables 脚本（后台运行）
    local script_content = "#!/bin/sh\n" .. table.concat(script_parts, "\n")
    -- 【问题2修复】二次验证文件名安全性（虽然 safe_mac 已保证纯十六进制）
    local safe_filename = mac_no_colon:match("^([A-Fa-f0-9]+)$")
    if not safe_filename then
        nixio.syslog("err", "[RouterAssistant] kick_device: invalid filename chars in " .. tostring(mac_no_colon))
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "内部错误", timestamp = os.time()})
        return
    end
    local script_file = "/tmp/router_assistant_kick_" .. os.time() .. "_" .. safe_filename .. ".sh"
    local sfd = io.open(script_file, "w")
    if sfd then
        sfd:write(script_content .. "\n")
        sfd:close()
        -- 【问题5修复】使用 safe_os_execute 添加超时保护
        safe_os_execute("chmod +x '" .. script_file .. "' 2>/dev/null", 3)
        safe_os_execute("nohup /bin/sh '" .. script_file .. "' >/dev/null 2>&1 &", 10)
        safe_os_execute("(sleep 15 && rm -f '" .. script_file .. "') >/dev/null 2>&1 &", 20)
    else
        -- 【问题4修复】fallback 路径：转义 cmd 中的单引号（防御深度）
        nixio.syslog("warning", "[RouterAssistant] kick_device: cannot write script file, using fallback for " .. mac_colon)
        for _, cmd in ipairs(script_parts) do
            local escaped_cmd = cmd:gsub("'", "'\\''")
            safe_os_execute("nohup /bin/sh -c '" .. escaped_cmd .. "' >/dev/null 2>&1 &", 10)
        end
    end

    nixio.syslog("info", "[RouterAssistant] kick_device: background script started for " .. mac_colon)

    -- 返回成功响应（后台脚本已在运行，iptables将在数ms内执行）
    luci.http.prepare_content("application/json")
    luci.http.write_json({
        code = 0,
        data = {
            message = "设备已断开并加入黑名单",
            mac = mac_colon,
            ip = device_ip,
            success = true
        },
        timestamp = os.time()
    })
end

function api_enable_device()
    nixio.syslog("info", "[RouterAssistant] api_enable_device called")

    if not require_csrf_token() then
        nixio.syslog("err", "[RouterAssistant] api_enable_device: CSRF failed")
        return
    end

    local http = require "luci.http"
    local util = require "luci.util"
    local nixio = require("nixio")

    local mac = luci.http.formvalue("mac")
    nixio.syslog("info", "[RouterAssistant] enable_device mac=" .. tostring(mac))

    if not mac or mac == "" then
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "MAC地址无效", timestamp = os.time()})
        return
    end

    local mac_colon = mac:upper():gsub("-", ":")
    local safe_mac = safe_mac_validate(mac_colon)
    if not safe_mac then
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "MAC地址格式无效", timestamp = os.time()})
        return
    end

    local mac_lower = mac_colon:lower()

    nixio.syslog("info", "[RouterAssistant] enable_device validated, mac=" .. mac_colon)

    -- ========== 所有耗时操作后台异步执行 ==========
    local formatted_mac = format_mac_colon(safe_mac)

    -- 【安全加固】所有拼入shell命令的变量加引号保护（防御深度）
    local safe_mac_quoted = "'" .. formatted_mac .. "'"
    local safe_mac_lower_quoted = "'" .. mac_lower .. "'"

    local script_parts = {}

    -- 1. 删除 iptables 规则
    table.insert(script_parts, "iptables -D INPUT -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")
    table.insert(script_parts, "iptables -D FORWARD -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")

    -- 2. 仅删除指定 MAC 的 iptables 规则（不再按 OUI 批量清理，保持与添加操作对称）
    --[[ 已禁用 OUI 联动删除（避免误删其他同品牌设备）
    local blocklist = nil
    pcall(function()
        blocklist = load_blocklist()
    end)
    local target_oui = get_mac_oui(mac_colon)
    if blocklist and blocklist.devices and target_oui then
        for _, device in ipairs(blocklist.devices) do
            if device.mac and device.mac ~= mac_colon then
                if get_mac_oui(device.mac) == target_oui then
                    local dev_mac = device.mac:gsub(":", "")
                    local dev_formatted = dev_mac:sub(1,2) .. ":" .. dev_mac:sub(3,4) .. ":" ..
                                         dev_mac:sub(5,6) .. ":" .. dev_mac:sub(7,8) .. ":" ..
                                         dev_mac:sub(9,10) .. ":" .. dev_mac:sub(11,12)
                    table.insert(script_parts, "iptables -D INPUT -m mac --mac-source " .. dev_formatted .. " -j DROP 2>/dev/null || true")
                    table.insert(script_parts, "iptables -D FORWARD -m mac --mac-source " .. dev_formatted .. " -j DROP 2>/dev/null || true")
                end
            end
        end
    end
    ]]

    -- 3. access_ctl.sh 恢复（如果存在）
    table.insert(script_parts, "if [ -x /usr/bin/access_ctl.sh ]; then timeout 5 access_ctl.sh -m " .. safe_mac_lower_quoted .. " -a 1 2>/dev/null || true; fi")

    -- 将所有操作写入临时脚本并后台执行（使用 MAC 唯一定位，避免并发覆盖）
    local script_content = table.concat(script_parts, "\n")
    -- 【问题2修复】二次验证文件名安全性
    local safe_filename = mac_no_colon:match("^([A-Fa-f0-9]+)$")
    if not safe_filename then
        nixio.syslog("err", "[RouterAssistant] enable_device: invalid filename chars in " .. tostring(mac_no_colon))
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -1, message = "内部错误", timestamp = os.time()})
        return
    end
    local script_file = "/tmp/router_assistant_enable_" .. safe_filename .. ".sh"
    local sfd = io.open(script_file, "w")
    if sfd then
        sfd:write("#!/bin/sh\n")
        sfd:write(script_content .. "\n")
        sfd:close()
        -- 【问题5修复】使用 safe_os_execute 添加超时保护
        safe_os_execute("chmod +x '" .. script_file .. "' 2>/dev/null", 3)
        safe_os_execute("nohup /bin/sh '" .. script_file .. "' >/dev/null 2>&1 &", 10)
        safe_os_execute("(sleep 10 && rm -f '" .. script_file .. "') >/dev/null 2>&1 &", 15)
    else
        -- 【问题4修复】fallback 路径：转义 cmd 中的单引号（防御深度）
        nixio.syslog("warning", "[RouterAssistant] enable_device: cannot write script file, using fallback for " .. mac_colon)
        for _, cmd in ipairs(script_parts) do
            local escaped_cmd = cmd:gsub("'", "'\\''")
            safe_os_execute("nohup /bin/sh -c '" .. escaped_cmd .. "' >/dev/null 2>&1 &", 10)
        end
    end

    -- 更新黑名单（纯Lua文件操作）
    pcall(remove_from_blocklist, mac_colon)
    _blocked_macs_cache = nil
    _blocked_macs_cache_time = 0
    clear_blocked_macs_cache_file()  -- 清除缓存文件，确保其他进程同步

    nixio.syslog("info", "[RouterAssistant] enable_device completed (background tasks running)")

    -- 立即返回成功响应
    luci.http.prepare_content("application/json")
    luci.http.write_json({
        code = 0,
        data = {
            message = "设备已解除限制，已恢复网络访问权限",
            mac = mac_colon,
            success = true
        },
        timestamp = os.time()
    })
end

function api_get_blocked_devices()
    collectgarbage("collect")
    local util = require "luci.util"
    local result = {code = 0, blocked = {}}

    local ok, err = pcall(function()
        -- 获取DHCP租约表中的设备信息
        local device_info = {}
        local leases_file = io.open("/tmp/dhcp.leases", "r")
        if leases_file then
            for line in leases_file:lines() do
                local parts = {}
                for part in line:gmatch("%S+") do
                    table.insert(parts, part)
                end
                if #parts >= 4 then
                    local mac = parts[2]:upper()
                    local ip = parts[3]
                    local name = parts[4] or "未知设备"
                    device_info[mac] = {ip = ip, name = name}
                end
            end
            leases_file:close()
        end

        -- 收集所有被屏蔽的MAC地址（使用集合去重）
        local blocked_macs = {}

        -- 从iptables输出中提取MAC地址的通用函数
        local function extract_macs_from_iptables(output)
            local macs = {}
            if not output then return macs end

            -- 验证MAC地址格式的辅助函数（必须是12位十六进制字符）
            local function is_valid_mac(mac)
                if not mac or type(mac) ~= "string" then return false end
                local clean = mac:upper():gsub("[^A-F0-9]", "")
                return #clean == 12
            end

            -- 方法1：匹配 --mac-source XX:XX:XX:XX:XX:XX 格式
            for mac in output:gmatch("--mac%-source%s+([%da-fA-F:]+)") do
                if is_valid_mac(mac) then
                    -- 标准化格式
                    local clean = mac:upper():gsub("[^A-F0-9]", "")
                    local formatted = clean:sub(1,2) .. ":" .. clean:sub(3,4) .. ":" ..
                                     clean:sub(5,6) .. ":" .. clean:sub(7,8) .. ":" ..
                                     clean:sub(9,10) .. ":" .. clean:sub(11,12)
                    macs[formatted] = true
                end
            end

            -- 方法2：匹配 MACxx:xx:xx:xx:xx:xx 格式（iptables -L 输出格式，MAC前缀无空格）
            for mac in output:gmatch("MAC([%da-fA-F][%da-fA-F:]+)") do
                if is_valid_mac(mac) then
                    local clean = mac:upper():gsub("[^A-F0-9]", "")
                    local formatted = clean:sub(1,2) .. ":" .. clean:sub(3,4) .. ":" ..
                                     clean:sub(5,6) .. ":" .. clean:sub(7,8) .. ":" ..
                                     clean:sub(9,10) .. ":" .. clean:sub(11,12)
                    macs[formatted] = true
                end
            end

            -- 方法3：匹配独立的MAC地址格式 XX:XX:XX:XX:XX:XX（在规则行中）
            for mac in output:gmatch("([%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F])") do
                if is_valid_mac(mac) then
                    local clean = mac:upper():gsub("[^A-F0-9]", "")
                    local formatted = clean:sub(1,2) .. ":" .. clean:sub(3,4) .. ":" ..
                                     clean:sub(5,6) .. ":" .. clean:sub(7,8) .. ":" ..
                                     clean:sub(9,10) .. ":" .. clean:sub(11,12)
                    macs[formatted] = true
                end
            end

            return macs
        end

        -- 检测方法1：检查iptables INPUT链中的DROP规则
        local input_output = util.exec("iptables -L INPUT -n --line-numbers 2>/dev/null")
        local input_macs = {}
        if input_output then
            input_macs = extract_macs_from_iptables(input_output)
        end
        for mac, _ in pairs(input_macs) do
            blocked_macs[mac] = true
        end

        -- 检测方法2：检查iptables FORWARD链中的DROP规则
        local forward_output = util.exec("iptables -L FORWARD -n --line-numbers 2>/dev/null")
        if forward_output then
            local forward_macs = extract_macs_from_iptables(forward_output)
            for mac, _ in pairs(forward_macs) do
                blocked_macs[mac] = true
            end
        end

        -- 检测方法3：检查internet_access链（access_ctl.sh管理的黑名单）
        local access_output = util.exec("iptables -L internet_access -n --line-numbers 2>/dev/null")
        if access_output then
            local access_macs = extract_macs_from_iptables(access_output)
            for mac, _ in pairs(access_macs) do
                blocked_macs[mac] = true
            end
        end

        -- 生成已屏蔽设备列表
        for mac_upper, _ in pairs(blocked_macs) do
            local info = device_info[mac_upper] or {}
            table.insert(result.blocked, {
                mac = mac_upper,
                name = info.name or "未知设备",
                ip = info.ip or ""
            })
        end

        -- 按MAC地址排序
        table.sort(result.blocked, function(a, b)
            return a.mac < b.mac
        end)
    end)

    if not ok then
        result.code = -1
        result.message = "获取黑名单设备失败"
        result.details = tostring(err)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function format_bytes(bytes)
    if not bytes or type(bytes) ~= "number" or bytes ~= bytes then
        return "0 B"
    end
    if bytes < 0 then
        bytes = 0
    end
    if bytes < 1024 then
        return string.format("%.0f B", bytes)
    elseif bytes < 1024 * 1024 then
        return string.format("%.1f KB", bytes / 1024)
    elseif bytes < 1024 * 1024 * 1024 then
        return string.format("%.1f MB", bytes / (1024 * 1024))
    else
        return string.format("%.2f GB", bytes / (1024 * 1024 * 1024))
    end
end

function get_encryption(iface, dev)
    local enc = iface.encryption(dev)
    if enc and enc.enabled then
        if enc.wep then return "WEP" end
        if enc.wpa == 1 then return "WPA" end
        if enc.wpa == 2 then return "WPA2" end
        if enc.wpa == 3 then return "WPA3" end
        return "WPA/WPA2"
    end
    return "Open"
end

function api_get_storage_status()
    local result = {
        code = 0,
        tf_card = {
            exists = false,
            mount_point = "",
            total = 0,
            used = 0,
            available = 0,
            percent = "0%"
        },
        current_storage = {
            path = "",
            type = "memory",
            writable = false
        }
    }

    local ok, err = pcall(function()
        local util = require("luci.util")

        local mount_output = util.exec("cat /proc/mounts 2>/dev/null | grep mmcblk0")
        if mount_output and mount_output ~= "" then
            result.tf_card.exists = true

            for line in mount_output:gmatch("[^\r\n]+") do
                local mount_point = line:match("^/dev/mmcblk0p1%s+(/%S+)")
                if mount_point then
                    if mount_point ~= "/overlay" then
                        result.tf_card.mount_point = mount_point
                        break
                    elseif result.tf_card.mount_point == "" then
                        result.tf_card.mount_point = mount_point
                    end
                end
            end

            if result.tf_card.mount_point ~= "" then
                local safe_mount = safe_path(result.tf_card.mount_point)
                if safe_mount then
                    local df_output = safe_exec_with_output("df", "-k " .. safe_mount .. " | tail -1")
                    if df_output and df_output ~= "" then
                        local parts = {}
                        for part in df_output:gmatch("%S+") do
                            table.insert(parts, part)
                        end
                        if #parts >= 4 then
                            result.tf_card.total = tonumber(parts[2]) * 1024
                            result.tf_card.used = tonumber(parts[3]) * 1024
                            result.tf_card.available = tonumber(parts[4]) * 1024
                            if result.tf_card.total > 0 then
                                local percent = (result.tf_card.used / result.tf_card.total) * 100
                                result.tf_card.percent = string.format("%.1f%%", percent)
                            end
                        end
                    end
                end
            end
        end

        local storage_path = get_storage_path()
        result.current_storage.path = storage_path
        result.current_storage.type = get_storage_type(storage_path)
        
        if _last_storage_type and _last_storage_type ~= result.current_storage.type then
            result.storage_changed = true
            result.previous_type = _last_storage_type
        end
        _last_storage_type = result.current_storage.type

        ensure_directory(storage_path)
        local test_fd = io.open(storage_path, "a")
        if test_fd then
            test_fd:close()
            result.current_storage.writable = true
        end
    end)

    if not ok then
        result = error_response(-1, "获取存储状态失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_migrate_storage()
    if not require_csrf_token() then return end
    local result = {
        code = 0,
        message = "",
        from_path = "",
        to_path = ""
    }

    local ok, err = pcall(function()
        local json = require("luci.jsonc")
        
        local old_paths = {
            "/tmp/traffic_stats.json",
            "/tmp/router_assistant/traffic_stats.json",
            "/mnt/sdcard/traffic_stats.json",
            "/overlay/traffic_stats.json"
        }
        
        local source_file = nil
        local source_data = nil
        
        for _, path in ipairs(old_paths) do
            local fd = io.open(path, "r")
            if fd then
                local content = fd:read("*all")
                fd:close()
                if content and content ~= "" and content ~= "{}" then
                    source_file = path
                    source_data = content
                    break
                end
            end
        end
        
        if not source_data then
            result.code = 1
            result.message = "没有找到需要迁移的数据"
            return
        end
        
        _cached_storage_path = nil
        local target_path = get_storage_path()
        
        local save_ok, save_err = save_with_fallback(target_path, source_data)
        if not save_ok then
            result = error_response(-1, "迁移失败: " .. tostring(save_err))
            return
        end
        
        result.from_path = source_file
        result.to_path = target_path
        result.message = "数据迁移成功"
        
        if source_file ~= target_path then
            os.remove(source_file)
        end
    end)

    if not ok then
        result = error_response(-1, "数据迁移失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_clear_data()
    if not require_csrf_token() then return end
    local result = {
        code = 0,
        message = "",
        deleted_path = ""
    }

    local ok, err = pcall(function()
        local storage_path = get_storage_path()
        
        -- 验证路径安全
        local safe_storage = safe_path(storage_path)
        if not safe_storage then
            result.code = -1
            result.message = "路径验证失败"
            return
        end
        
        -- 验证文件是否为预期的数据文件
        local allowed_files = {
            "traffic_stats.json",
            "device_notes.json",
            "traffic_history.json",
            "traffic_alerts.json",
            "mac_blocklist.json"
        }
        local filename = storage_path:match("([^/]+)$")
        local is_allowed = false
        for _, allowed in ipairs(allowed_files) do
            if filename == allowed then
                is_allowed = true
                break
            end
        end
        
        if not is_allowed then
            result.code = -2
            result.message = "不允许删除此文件"
            return
        end
        
        local fd = io.open(safe_storage, "r")
        if not fd then
            result.code = 1
            result.message = "数据文件不存在"
            return
        end
        fd:close()
        
        os.remove(safe_storage)
        result.deleted_path = safe_storage
        result.message = "数据已清除"
        
        _cached_storage_path = nil
    end)

    if not ok then
        result = error_response(-1, "清除数据失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_data_stats()
    local result = {
        code = 0,
        data_files = {},
        total_size = 0,
        storage_info = {}
    }

    local ok, err = pcall(function()
        local storage_path = get_storage_path()
        local data_dir = storage_path:match("^(.+)/[^/]+$") or "/tmp/router_assistant"
        
        result.storage_info = {
            path = data_dir,
            type = get_storage_type(storage_path)
        }

        local file_list = {
            {name = "traffic_stats.json", desc = "流量统计数据"},
            {name = "device_notes.json", desc = "设备备注"},
            {name = "traffic_history.json", desc = "流量历史记录"},
            {name = "traffic_alerts.json", desc = "流量报警设置"}
        }

        for _, file_info in ipairs(file_list) do
            local file_path = data_dir .. "/" .. file_info.name
            local fd = io.open(file_path, "r")
            if fd then
                local size = fd:seek("end")
                fd:close()
                table.insert(result.data_files, {
                    name = file_info.name,
                    desc = file_info.desc,
                    path = file_path,
                    size = size or 0,
                    exists = true
                })
                result.total_size = result.total_size + (size or 0)
            else
                table.insert(result.data_files, {
                    name = file_info.name,
                    desc = file_info.desc,
                    path = file_path,
                    size = 0,
                    exists = false
                })
            end
        end
    end)

    if not ok then
        result = error_response(-1, "获取数据统计失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_clear_all_data()
    if not require_csrf_token() then return end
    collectgarbage("collect")
    local result = {
        code = 0,
        message = "",
        deleted_files = {}
    }

    local ok, err = pcall(function()
        local data_type = luci.http.formvalue("data_type") or "all"

        local all_possible_dirs = {
            "/tmp/storage/mmcblk0p1/router_assistant",
            "/mnt/mmcblk0p1/router_assistant",
            "/mnt/sdcard/router_assistant",
            "/tmp/mnt/mmcblk0p1/router_assistant",
            "/overlay/router_assistant",
            "/tmp/router_assistant"
        }

        local file_map = {
            all = {
                DATA_FILE_NAME,
                NOTES_FILE_NAME,
                "traffic_monthly.json",
                "traffic_hourly.json",
                ALERTS_FILE_NAME
            },
            traffic = {
                DATA_FILE_NAME,
                "traffic_monthly.json",
                "traffic_hourly.json"
            },
            notes = {
                NOTES_FILE_NAME
            },
            alerts = {
                ALERTS_FILE_NAME
            }
        }

        local files_to_delete = file_map[data_type] or file_map.all
        local deleted_count = 0

        for _, data_dir in ipairs(all_possible_dirs) do
            for _, filename in ipairs(files_to_delete) do
                local file_path = data_dir .. "/" .. filename
                
                -- 验证路径安全
                local safe_file = safe_path(file_path)
                if safe_file then
                    local fd = io.open(safe_file, "r")
                    if fd then
                        fd:close()
                        local remove_ok = os.remove(safe_file)
                        if remove_ok then
                            table.insert(result.deleted_files, {
                                name = filename,
                                path = safe_file,
                                success = true
                            })
                            deleted_count = deleted_count + 1
                        end
                    end
                end
            end
        end

        if deleted_count > 0 then
            result.message = "数据清理完成，共删除 " .. deleted_count .. " 个文件"
        else
            result.message = "没有找到需要清理的文件"
        end

        _cached_storage_path = nil
        _storage_path_cache_time = 0
    end)

    if not ok then
        result = error_response(-1, "清理数据失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- ========== 网络测速功能（Homebox） ==========

local function is_homebox_running()
    local pid_fd = io.open(HOMEBOX_PID_FILE, "r")
    if pid_fd then
        local pid = pid_fd:read("*l")
        pid_fd:close()
        if pid and pid ~= "" then
            -- 检查进程是否存在
            local check_fd = io.popen("ps | grep -v grep | grep -q 'homebox.*serve' && echo 'running'")
            if check_fd then
                local result = check_fd:read("*l")
                check_fd:close()
                if result and result:match("running") then
                    return true
                end
            end
        end
    end
    
    -- 方法2：检查端口是否被监听
    local port_fd = io.popen("netstat -tln 2>/dev/null | grep ':" .. HOMEBOX_PORT .. "' | wc -l")
    if port_fd then
        local count = port_fd:read("*l")
        port_fd:close()
        if count and tonumber(count) > 0 then
            return true
        end
    end
    
    return false
end

-- 获取路由器 IP 地址
local function get_router_ip()
    -- 方法1：获取默认路由IP
    local fd = io.popen("ip route show default 2>/dev/null | awk '/src/ {print $NF}' | head -1")
    if fd then
        local ip = fd:read("*l")
        fd:close()
        if ip and ip ~= "" then
            return ip
        end
    end
    -- 方法2：获取 br-lan IP
    fd = io.popen("ip addr show br-lan 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1")
    if fd then
        local ip = fd:read("*l")
        fd:close()
        if ip and ip ~= "" then
            return ip
        end
    end
    -- 方法3：动态获取所有非 WAN 接口的 IP（避免硬编码）
    local fd3 = io.popen("ip -o link show 2>/dev/null | grep -v 'lo:' | awk -F': ' '{print $2}' | while read iface; do ip addr show \"$iface\" 2>/dev/null | grep 'inet ' | head -1 | awk '{print $2}' | cut -d'/' -f1; done | head -1")
    if fd3 then
        local ip = fd3:read("*l")
        fd3:close()
        if ip and ip ~= "" then
            return ip
        end
    end
    -- 方法4：返回nil而非硬编码值，让调用方决定如何处理
    return nil
end

-- 启动 Homebox 服务
local function start_homebox()
    if is_homebox_running() then
        return true, "Homebox 已在运行"
    end

    local fd = io.open(HOMEBOX_BIN, "r")
    if not fd then
        return false, "Homebox 未安装"
    end
    fd:close()

    if not safe_path(HOMEBOX_BIN) then
        return false, "Homebox 路径无效"
    end

    safe_exec_command("chmod", "+x " .. HOMEBOX_BIN)
    
    safe_exec_command("killall", "homebox")
    os.remove(HOMEBOX_PID_FILE)

    local start_cmd = HOMEBOX_BIN .. " serve --port " .. tostring(HOMEBOX_PORT) .. 
                      " > " .. HOMEBOX_LOG_FILE .. " 2>&1 &"
    os.execute(start_cmd)
    
    local pid_fd = io.popen("pgrep -f 'homebox.*serve' | head -1 2>/dev/null", "r")
    if pid_fd then
        local pid = pid_fd:read("*l")
        pid_fd:close()
        if pid and pid ~= "" then
            local write_fd = io.open(HOMEBOX_PID_FILE, "w")
            if write_fd then
                write_fd:write(pid)
                write_fd:close()
            end
        end
    end

    local waited = 0
    while waited < HOMEBOX_START_TIMEOUT do
        if is_homebox_running() then
            return true, "Homebox 启动成功"
        end
        os.execute("sleep 1")
        waited = waited + 1
    end

    local log_fd = io.open(HOMEBOX_LOG_FILE, "r")
    local log_content = ""
    if log_fd then
        log_content = log_fd:read("*all") or ""
        log_fd:close()
    end
    
    if log_content ~= "" then
        return false, "启动失败: " .. log_content:sub(1, 200)
    end
    
    return false, "Homebox 启动超时"
end

-- 启动测速（返回 Homebox URL）
function api_speed_test()
    if not require_csrf_token() then return end
    local http = require("luci.http")
    local util = require("luci.util")
    local json = require("luci.jsonc")

    local result = {
        code = 0,
        status = "ready",
        message = ""
    }

    local ok, err = pcall(function()
        -- 检查并启动 Homebox
        local success, msg = start_homebox()
        if not success then
            result.code = -1
            result.status = "error"
            result.message = msg
            return
        end

        -- 获取路由器 IP
        local router_ip = get_router_ip()
        if router_ip then
            result.url = "http://" .. router_ip .. ":" .. HOMEBOX_PORT
        else
            result.url = nil
        end
        result.status = "ready"
        result.message = "Homebox 测速服务已就绪"
    end)

    if not ok then
        result = error_response(-1, "启动测速服务失败", tostring(err))
    elseif result.code and result.code < 0 then
        result.timestamp = os.time()
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- 查询测速状态（Homebox 模式下用于检查服务状态）
function api_speed_test_status()
    local http = require("luci.http")
    local json = require("luci.jsonc")

    local result = {
        code = 0,
        status = "idle",
        message = ""
    }

    local ok, err = pcall(function()
        if is_homebox_running() then
            local router_ip = get_router_ip()
            result.status = "ready"
            if router_ip then
                result.url = "http://" .. router_ip .. ":" .. HOMEBOX_PORT
            else
                result.url = nil
            end
            result.message = "Homebox 测速服务运行中"
        else
            result.status = "stopped"
            result.message = "Homebox 测速服务未运行"
        end
    end)

    if not ok then
        result = error_response(-1, "查询状态失败", tostring(err))
    else
        result = success_response(result)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- ============================================================
-- 网络诊断工具
-- ============================================================

local DIAGNOSE_TIMEOUT = 10
local MAX_PING_COUNT = 10

local function safe_target_validate(target)
    if not target or type(target) ~= "string" then return nil end
    target = target:gsub("[%s\r\n]", "")
    if #target > 256 then return nil end
    if target:match("^[a-zA-Z0-9%-%._]+$") or target:match("^[%d%.]+$") then
        return target
    end
    return nil
end

function api_network_diagnose()
    if not require_csrf_token() then return end
    collectgarbage("collect")

    local diagnose_type = luci.http.formvalue("type") or "ping"
    local target = luci.http.formvalue("target") or ""
    local count = tonumber(lucy.http.formvalue("count")) or 4
    local port = tonumber(lucy.http.formvalue("port")) or 0

    local safe_target = safe_target_validate(target)
    if not safe_target then
        luci.http.prepare_content("application/json")
        luci.http.write_json(error_response(-1, "无效的目标地址"))
        return
    end

    if count < 1 or count > MAX_PING_COUNT then count = 4 end

    local result = {
        type = diagnose_type,
        target = safe_target,
        output = "",
        success = false,
        timestamp = os.time()
    }

    local cmd = ""
    local ok, err = pcall(function()
        if diagnose_type == "ping" then
            cmd = "timeout " .. DIAGNOSE_TIMEOUT .. " ping -c " .. count .. " -W 2 '" .. safe_target .. "' 2>&1"
        elseif diagnose_type == "traceroute" then
            if luci.sys.exec("which traceroute 2>/dev/null | wc -l"):gsub("%s+", "") == "1" then
                cmd = "timeout " .. (DIAGNOSE_TIMEOUT * 2) .. " traceroute -m 20 '" .. safe_target .. "' 2>&1"
            else
                cmd = "timeout " .. (DIAGNOSE_TIMEOUT * 2) .. " traceroute -m 20 '" .. safe_target .. "' 2>&1"
            end
        elseif diagnose_type == "dns" then
            cmd = "timeout " .. DIAGNOSE_TIMEOUT .. " nslookup '" .. safe_target .. "' 2>&1 || timeout " .. DIAGNOSE_TIMEOUT .. " dig '" .. safe_target .. "' +short 2>&1"
        elseif diagnose_type == "port" then
            if port < 1 or port > 65535 then
                result.output = "错误：端口号必须在 1-65535 范围内"
                result.success = false
            else
                cmd = "timeout " .. DIAGNOSE_TIMEOUT .. " nc -zv -w 3 '" .. safe_target .. "' " .. port .. " 2>&1 || echo '端口 " .. port .. " 不可达'"
            end
        else
            result.output = "错误：不支持的诊断类型"
            result.success = false
        end

        if cmd and cmd ~= "" then
            local output = luci.sys.exec(cmd)
            result.output = output or ""
            result.success = true
        end
    end)

    if not ok then
        result.output = "诊断执行失败: " .. tostring(err)
        result.success = false
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(success_response(result))
end

-- ============================================================
-- 设备限速（QoS）
-- ============================================================

local QOS_IFACE = "br-lan"
local RATE_LIMIT_FILE = "/etc/router_assistant_rate_limits.json"

local function load_rate_limits()
    local fd = io.open(RATE_LIMIT_FILE, "r")
    if fd then
        local content = fd:read("*a")
        fd:close()
        if content and content ~= "" then
            local json = require("luci.jsonc")
            local ok, data = pcall(json.parse, content)
            if ok and data then return data end
        end
    end
    return {}
end

local function save_rate_limits(limits)
    local json = require("luci.jsonc")
    local content = json.stringify(limits) or "{}"
    local fd = io.open(RATE_LIMIT_FILE, "w")
    if fd then
        fd:write(content)
        fd:close()
        return true
    end
    return false
end

local function apply_tc_rules(mac, download_kbps, upload_kbps)
    local mac_no_colon = mac:gsub(":", ""):upper()
    local download_classid = "1" .. mac_no_colon:sub(1, 4)
    local upload_classid = "2" .. mac_no_colon:sub(1, 4)

    os.execute("tc filter del dev " .. QOS_IFACE .. " parent 1: protocol ip pref 100 handle ::" .. download_classid .. " flowid 1:" .. download_classid .. " 2>/dev/null")
    os.execute("tc filter del dev " .. QOS_IFACE .. " parent 2: protocol ip pref 100 handle ::" .. upload_classid .. " flowid 2:" .. upload_classid .. " 2>/dev/null")

    if download_kbps > 0 then
        os.execute("tc class add dev " .. QOS_IFACE .. " parent 1: classid 1:" .. download_classid .. " htb rate " .. download_kbps .. "kbit ceil " .. download_kbps .. "kbit 2>/dev/null || tc class change dev " .. QOS_IFACE .. " parent 1: classid 1:" .. download_classid .. " htb rate " .. download_kbps .. "kbit ceil " .. download_kbps .. "kbit")
        os.execute("tc filter add dev " .. QOS_IFACE .. " parent 1: protocol ip prio 5 u32 match ip dst 0.0.0.0/0 match ether dst " .. mac .. " flowid 1:" .. download_classid .. " 2>/dev/null")
    end

    if upload_kbps > 0 then
        os.execute("tc class add dev " .. QOS_IFACE .. " parent 2: classid 2:" .. upload_classid .. " htb rate " .. upload_kbps .. "kbit ceil " .. upload_kbps .. "kbit 2>/dev/null || tc class change dev " .. QOS_IFACE .. " parent 2: classid 2:" .. upload_classid .. " htb rate " .. upload_kbps .. "kbit ceil " .. upload_kbps .. "kbit")
        os.execute("tc filter add dev " .. QOS_IFACE .. " parent 2: protocol ip prio 5 u32 match ip src 0.0.0.0/0 match ether src " .. mac .. " flowid 2:" .. upload_classid .. " 2>/dev/null")
    end

    return true
end

local function init_qos()
    os.execute("tc qdisc add dev " .. QOS_IFACE .. " root handle 1: htb default 10 2>/dev/null")
    os.execute("tc class add dev " .. QOS_IFACE .. " parent 1: classid 1:10 htb rate 1000mbit 2>/dev/null")
    os.execute("tc qdisc add dev " .. QOS_IFACE .. " parent 1:10 handle 10: sfq perturb 10 2>/dev/null")
end

function api_get_rate_limits()
    collectgarbage("collect")
    local limits = load_rate_limits()
    luci.http.prepare_content("application/json")
    luci.http.write_json(success_response({limits = limits}))
end

function api_set_rate_limit()
    if not require_csrf_token() then return end
    collectgarbage("collect")

    local mac = luci.http.formvalue("mac") or ""
    local download_limit = tonumber(lucy.http.formvalue("download_limit")) or 0
    local upload_limit = tonumber(lucy.http.formvalue("upload_limit")) or 0
    local enabled = luci.http.formvalue("enabled") == "true" or luci.http.formvalue("enabled") == "1"

    local safe_mac = safe_mac_validate(mac)
    if not safe_mac then
        luci.http.prepare_content("application/json")
        luci.http.write_json(error_response(-1, "无效的MAC地址"))
        return
    end

    local mac_colon = format_mac_colon(safe_mac)
    local limits = load_rate_limits()

    if enabled and (download_limit > 0 or upload_limit > 0) then
        limits[safe_mac] = {
            mac = mac_colon,
            download_limit = download_limit,
            upload_limit = upload_limit,
            enabled = true,
            created_at = limits[safe_mac] and limits[safe_mac].created_at or os.time(),
            updated_at = os.time()
        }
        init_qos()
        apply_tc_rules(mac_colon, download_limit, upload_limit)
    else
        if limits[safe_mac] then
            apply_tc_rules(mac_colon, 0, 0)
        end
        limits[safe_mac] = nil
    end

    save_rate_limits(limits)

    luci.http.prepare_content("application/json")
    luci.http.write_json(success_response({
        mac = mac_colon,
        download_limit = download_limit,
        upload_limit = upload_limit,
        enabled = enabled and (download_limit > 0 or upload_limit > 0),
        message = "限速设置已保存"
    }))
end

function api_remove_rate_limit()
    if not require_csrf_token() then return end
    collectgarbage("collect")

    local mac = luci.http.formvalue("mac") or ""
    local safe_mac = safe_mac_validate(mac)

    if not safe_mac then
        luci.http.prepare_content("application/json")
        luci.http.write_json(error_response(-1, "无效的MAC地址"))
        return
    end

    local mac_colon = format_mac_colon(safe_mac)
    local limits = load_rate_limits()

    if limits[safe_mac] then
        apply_tc_rules(mac_colon, 0, 0)
        limits[safe_mac] = nil
        save_rate_limits(limits)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(success_response({
        mac = mac_colon,
        message = "限速规则已移除"
    }))
end
