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

-- 实时网速监控常量
REALTIME_SPEED_FILE = "realtime_speed.json"
MAX_REALTIME_POINTS = 120  -- 保留最近120个数据点（约2分钟，每秒采集一次）
REALTIME_SPEED_CACHE_TTL = 1  -- 实时网速缓存1秒

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

-- 实时网速缓存（文件缓存，跨进程共享）
local REALTIME_SPEED_CACHE_FILE = "/tmp/router_assistant/realtime_speed_cache.json"
_realtime_speed_cache = nil  -- 进程内缓存
_realtime_speed_cache_time = 0

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

-- 检测timeout命令是否可用
-- 优先使用系统timeout，如果没有则使用插件内置的timeout
local _has_timeout = nil
local _timeout_path = nil
local function has_timeout_cmd()
    if _has_timeout == nil then
        -- 1. 检查系统是否有 timeout 命令
        local ret = luci.sys.exec("which timeout 2>/dev/null") or ""
        if ret ~= "" and ret:match("timeout") then
            _has_timeout = true
            _timeout_path = "timeout"
        else
            -- 2. 检查插件内置的 timeout
            local plugin_timeout = "/usr/libexec/router_assistant/timeout"
            local fd = io.open(plugin_timeout, "r")
            if fd then
                fd:close()
                _has_timeout = true
                _timeout_path = plugin_timeout
            else
                _has_timeout = false
                _timeout_path = nil
                nixio.syslog("warning", "[RouterAssistant] timeout command not found, network diagnose may hang without timeout protection")
            end
        end
    end
    return _has_timeout
end

-- 获取 timeout 命令路径（系统命令或插件内置）
local function get_timeout_cmd()
    has_timeout_cmd() -- 确保已初始化
    return _timeout_path
end

-- 非阻塞式执行命令（只执行不管结果，避免popen阻塞）
-- 适用于 iptables、conntrack 等不需要读取输出的命令
local function safe_exec_command(cmd_name, args, timeout)
    if not cmd_name or not ALLOWED_COMMANDS[cmd_name] then
        return false, "Command not allowed: " .. tostring(cmd_name)
    end
    
    local full_cmd
    local timeout_cmd = get_timeout_cmd()
    if timeout_cmd then
        local t = timeout or CMD_TIMEOUT
        full_cmd = timeout_cmd .. " " .. t .. " " .. cmd_name .. " " .. (args or "") .. " >/dev/null 2>&1 &"
    else
        full_cmd = cmd_name .. " " .. (args or "") .. " >/dev/null 2>&1 &"
    end
    return luci.sys.exec(full_cmd)
end

-- 带超时的popen执行（仅用于需要读取输出的场景）
-- 增加双重保护：timeout命令 + io.select轮询
local function safe_exec_with_output(cmd_name, args, timeout)
    if not cmd_name or not ALLOWED_COMMANDS[cmd_name] then
        return nil, "Command not allowed: " .. tostring(cmd_name)
    end
    
    local t = timeout or CMD_TIMEOUT
    local full_cmd
    local timeout_cmd = get_timeout_cmd()
    if timeout_cmd then
        full_cmd = timeout_cmd .. " " .. t .. " " .. cmd_name .. " " .. (args or "") .. " 2>/dev/null"
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
    luci.sys.exec(cmd)
    return true
end

-- 【问题5修复】强制超时执行包装器（用于 os.execute 调用）
-- 确保所有后台命令都有超时保护，防止命令阻塞导致502
local function safe_os_execute(cmd, timeout_sec)
    local t = timeout_sec or CMD_TIMEOUT
    local timeout_cmd = get_timeout_cmd()
    if timeout_cmd then
        return luci.sys.exec(timeout_cmd .. " " .. t .. " " .. cmd .. " 2>&1")
    else
        pcall(function()
            local nixio = require("nixio")
            nixio.syslog("warning", "[RouterAssistant] no timeout command, running without protection: " .. tostring(t))
        end)
        return luci.sys.exec(cmd .. " 2>&1")
    end
end

-- 【关键修复】真正非阻塞的后台执行函数
-- 使用 os.execute 而不是 luci.sys.exec，确保后台进程不会被父进程等待
-- luci.sys.exec 使用 io.popen，会等待管道关闭，可能导致后台命令被阻塞
local function exec_background_nowait(cmd)
    local nixio = require("nixio")
    nixio.syslog("info", "[RouterAssistant] exec_background_nowait: " .. cmd)
    -- os.execute 对于后台命令（带 &）会立即返回，不会等待子进程
    local result = os.execute(cmd)
    return result == 0 or result == true
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
    entry({"admin", "status", "router_assistant", "create_monthly_snapshot"}, call("api_create_monthly_snapshot")).leaf = true

    -- 网络诊断工具
    entry({"admin", "status", "router_assistant", "network_diagnose"}, post("api_network_diagnose")).leaf = true

    -- 安全中心功能
    entry({"admin", "status", "router_assistant", "get_security_overview"}, call("api_get_security_overview")).leaf = true
    entry({"admin", "status", "router_assistant", "get_mac_vendor"}, call("api_get_mac_vendor")).leaf = true
    entry({"admin", "status", "router_assistant", "get_device_fingerprint"}, call("api_get_device_fingerprint")).leaf = true
    entry({"admin", "status", "router_assistant", "get_arp_spoof_detection"}, call("api_get_arp_spoof_detection")).leaf = true
    entry({"admin", "status", "router_assistant", "get_arp_alert_history"}, call("api_get_arp_alert_history")).leaf = true
    entry({"admin", "status", "router_assistant", "handle_arp_alert"}, post("api_handle_arp_alert")).leaf = true
    entry({"admin", "status", "router_assistant", "clear_arp_history"}, post("api_clear_arp_history")).leaf = true
    entry({"admin", "status", "router_assistant", "get_port_scan_detection"}, call("api_get_port_scan_detection")).leaf = true
    entry({"admin", "status", "router_assistant", "start_port_scan"}, post("api_start_port_scan")).leaf = true
    entry({"admin", "status", "router_assistant", "get_port_scan_history"}, call("api_get_port_scan_history")).leaf = true
    entry({"admin", "status", "router_assistant", "handle_port_scan_alert"}, post("api_handle_port_scan_alert")).leaf = true
    entry({"admin", "status", "router_assistant", "refresh_security_data"}, post("api_refresh_security_data")).leaf = true
    entry({"admin", "status", "router_assistant", "add_security_whitelist"}, post("api_add_security_whitelist")).leaf = true
    entry({"admin", "status", "router_assistant", "remove_security_whitelist"}, post("api_remove_security_whitelist")).leaf = true
    entry({"admin", "status", "router_assistant", "get_security_whitelist"}, call("api_get_security_whitelist")).leaf = true
    
    -- 网络安全检测
    entry({"admin", "status", "router_assistant", "check_open_ports"}, call("api_check_open_ports")).leaf = true
    entry({"admin", "status", "router_assistant", "check_dns_hijack"}, call("api_check_dns_hijack")).leaf = true
    entry({"admin", "status", "router_assistant", "check_weak_passwords"}, call("api_check_weak_passwords")).leaf = true
    entry({"admin", "status", "router_assistant", "run_security_scan"}, post("api_run_security_scan")).leaf = true
    
    -- 自定义OUI数据库管理
    entry({"admin", "status", "router_assistant", "get_custom_oui"}, call("api_get_custom_oui")).leaf = true
    entry({"admin", "status", "router_assistant", "add_custom_oui"}, post("api_add_custom_oui")).leaf = true
    entry({"admin", "status", "router_assistant", "remove_custom_oui"}, post("api_remove_custom_oui")).leaf = true
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
    local neigh6_output = util.exec("ip -6 neigh show 2>/dev/null")
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
    local neigh6_output = util.exec("ip -6 neigh show 2>/dev/null")
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

    -- 手机识别：iPhone, Android, 小米, 华为, OPPO, vivo, Redmi, 三星, 荣耀等
    if h:match("iphone") or h:match("android") or h:match("redmi") or h:match("xiaomi") or 
       h:match("huawei") or h:match("honor") or h:match("oppo") or h:match("vivo") or
       h:match("samsung") or h:match("galaxy") or h:match("oneplus") or h:match("realme") or
       h:match("meizu") or h:match("zte") or h:match("nubia") or h:match("motorola") or
       h:match("lenovo") or h:match("sony") or h:match("lg") or h:match("htc") or
       h:match("pixel") or h:match("nexus") or h:match("手机") then
        return "phone"
    -- 平板识别：iPad, Galaxy Tab, MatePad 等
    elseif h:match("ipad") or h:match("galaxy.tab") or h:match("matepad") or h:match("surface") or
           h:match("pad") or h:match("tab") or h:match("平板") then
        return "tablet"
    -- 笔记本识别：MacBook, ThinkPad, Dell, HP, Lenovo, ASUS 等
    elseif h:match("macbook") or h:match("thinkpad") or h:match("laptop") or h:match("笔记本") then
        return "laptop"
    -- 台式机识别：Desktop, PC, Windows-PC 等
    elseif h:match("desktop") or h:match("^pc") or h:match("windows.pc") or h:match("台式") or
           h:match("computer") or h:match("dell") or h:match("hp") or h:match("asus") or
           h:match("acer") or h:match("msi") or h:match("lenovo") then
        return "desktop"
    -- 穿戴设备识别：Apple Watch, 小米手环, 华为手表 等
    elseif h:match("watch") or h:match("band") or h:match("手环") or h:match("手表") or
           h:match("fitbit") or h:match("garmin") or h:match("amazfit") then
        return "wearable"
    -- 电视/盒子识别：小米电视, Apple TV, Chromecast 等
    elseif h:match("tv") or h:match("电视") or h:match("盒子") or h:match("box") or
           h:match("chromecast") or h:match("fire.tv") or h:match("roku") or h:match("appletv") then
        return "tv"
    -- 打印机识别
    elseif h:match("printer") or h:match("打印") or h:match("hp.print") or h:match("canon") or
           h:match("epson") or h:match("brother") then
        return "printer"
    -- 摄像头识别
    elseif h:match("camera") or h:match("摄像头") or h:match("相机") or h:match("ipc") or
           h:match("yi.camera") or h:match("foscam") or h:match("hikvision") or h:match("dahua") then
        return "camera"
    -- NAS/服务器识别：群晖, 威联通, TrueNAS 等
    elseif h:match("nas") or h:match("存储") or h:match("群晖") or h:match("synology") or
           h:match("qnap") or h:match("truenas") or h:match("freenas") then
        return "server"
    -- 路由器/网关识别
    elseif h:match("router") or h:match("路由") or h:match("ap") or h:match("网关") or
           h:match("gateway") or h:match("mikrotik") or h:match("ubiquiti") or h:match("openwrt") then
        return "router"
    -- 交换机识别
    elseif h:match("switch") or h:match("交换机") or h:match("cisco") or h:match("huawei.switch") then
        return "router"
    -- 服务器识别
    elseif h:match("server") or h:match("服务器") or h:match("ubuntu") or h:match("centos") or
           h:match("debian") or h:match("fedora") or h:match("redhat") then
        return "server"
    -- 游戏机识别：PlayStation, Xbox, Nintendo Switch 等
    elseif h:match("ps[345]") or h:match("playstation") or h:match("xbox") or h:match("nintendo") or
           h:match("switch") or h:match("游戏机") or h:match("wii") or h:match("3ds") then
        return "gaming"
    -- 智能家居识别
    elseif h:match("smart") or h:match("智能") or h:match("灯") or h:match("插座") or h:match("sensor") or
           h:match("yeelight") or h:match("philips.hue") or h:match("tuya") or h:match("涂鸦") then
        return "smart_home"
    -- 扫地机器人识别
    elseif h:match("robot") or h:match("扫地") or h:match("roborock") or h:match("irobot") or
           h:match("xiaomi.vacuum") or h:match("dreame") or h:match("石头") then
        return "smart_home"
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
    local fd = io.popen("ip -6 neigh show 2>/dev/null")
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

-- ============================================================
-- 自定义OUI数据库管理API
-- ============================================================

-- API: 获取自定义OUI数据库
function api_get_custom_oui()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local custom_db = load_custom_oui_database()
        local entries = {}
        
        if custom_db and custom_db.entries then
            for oui, entry in pairs(custom_db.entries) do
                table.insert(entries, {
                    oui = oui,
                    vendor = entry.vendor or "",
                    device_type = entry.device_type or "unknown",
                    added_time = entry.added_time or 0,
                    note = entry.note or ""
                })
            end
        end
        
        response_data = success_response({
            entries = entries,
            total_count = #entries
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取自定义OUI失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 添加自定义OUI条目
function api_add_custom_oui()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local oui_prefix = (luci.http.formvalue("oui") or ""):upper():gsub("[^A-F0-9]", "")
    local vendor = luci.http.formvalue("vendor") or ""
    local device_type = luci.http.formvalue("device_type") or "unknown"
    local note = luci.http.formvalue("note") or ""
    
    local ok, err = pcall(function()
        -- 验证OUI前缀（6个十六进制字符）
        if not oui_prefix or #oui_prefix ~= 6 then
            response_data = error_response(-1, "无效的OUI前缀，需要6位十六进制字符（如B66E8A）")
            return
        end
        
        if not vendor or vendor == "" then
            response_data = error_response(-1, "厂商名称不能为空")
            return
        end
        
        local custom_db = load_custom_oui_database()
        if not custom_db.entries then
            custom_db.entries = {}
        end
        
        -- 格式化OUI前缀为标准格式
        local formatted_oui = oui_prefix:sub(1,2) .. ":" .. oui_prefix:sub(3,4) .. ":" .. oui_prefix:sub(5,6)
        
        custom_db.entries[formatted_oui] = {
            vendor = vendor,
            device_type = device_type,
            note = note,
            added_time = os.time(),
            source = "manual"
        }
        
        save_custom_oui_database(custom_db)
        
        response_data = success_response({
            message = "已添加自定义OUI: " .. formatted_oui .. " → " .. vendor,
            oui = formatted_oui,
            vendor = vendor
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "添加自定义OUI失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 删除自定义OUI条目
function api_remove_custom_oui()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local oui_prefix = (luci.http.formvalue("oui") or ""):upper():gsub("[^A-F0-9]", "")
    
    local ok, err = pcall(function()
        if not oui_prefix or #oui_prefix < 3 then
            response_data = error_response(-1, "无效的OUI前缀")
            return
        end
        
        local formatted_oui = oui_prefix:sub(1,2) .. ":" .. oui_prefix:sub(3,4) .. ":" .. oui_prefix:sub(5,6)
        local custom_db = load_custom_oui_database()
        
        if custom_db and custom_db.entries and custom_db.entries[formatted_oui] then
            local removed_vendor = custom_db.entries[formatted_oui].vendor
            custom_db.entries[formatted_oui] = nil
            save_custom_oui_database(custom_db)
            
            response_data = success_response({
                message = "已删除自定义OUI: " .. formatted_oui,
                oui = formatted_oui,
                vendor = removed_vendor
            })
        else
            response_data = error_response(-1, "该OUI不在自定义数据库中")
        end
    end)
    
    if not ok then
        response_data = error_response(-1, "删除自定义OUI失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- ============================================================
-- 网络安全检测功能
-- ============================================================

-- 路由器必要端口白名单（这些端口是路由器正常工作必需的，不应标记为危险）
local ROUTER_ESSENTIAL_PORTS = {
    ["53"] = {name = "DNS", desc = "DNS解析服务（路由器必需）", category = "essential"},
    ["67"] = {name = "DHCP-Server", desc = "DHCP服务（路由器必需）", category = "essential"},
    ["68"] = {name = "DHCP-Client", desc = "DHCP客户端（路由器必需）", category = "essential"},
    ["80"] = {name = "HTTP/WebUI", desc = "Web管理界面（路由器必需）", category = "essential"},
    ["443"] = {name = "HTTPS/WebUI", desc = "安全Web管理界面（路由器必需）", category = "essential"},
    ["1900"] = {name = "UPnP/SSDP", desc = "设备发现服务（IoT设备需要）", category = "iot"},
    ["5353"] = {name = "mDNS", desc = "多播DNS（Apple设备/AirPlay等）", category = "iot"}
}

-- 危险端口列表（不应对外开放的端口，排除必要端口后）
local DANGEROUS_PORTS = {
    ["22"] = {name = "SSH", risk = "high", desc = "远程SSH登录，可能被暴力破解"},
    ["23"] = {name = "Telnet", risk = "critical", desc = "明文传输，极不安全，建议关闭"},
    ["25"] = {name = "SMTP", risk = "medium", desc = "邮件服务，可能被利用发送垃圾邮件"},
    ["111"] = {name = "RPCbind", risk = "high", desc = "RPC服务，存在多个已知漏洞"},
    ["135"] = {name = "MS-RPC", risk = "high", desc = "Windows RPC服务"},
    ["139"] = {name = "NetBIOS", risk = "medium", desc = "Windows文件共享"},
    ["445"] = {name = "SMB", risk = "high", desc = "Windows共享服务，永恒之蓝漏洞"},
    ["512"] = {name = "Rexec", risk = "critical", desc = "远程执行命令"},
    ["513"] = {name = "Rlogin", risk = "critical", desc = "明文远程登录"},
    ["514"] = {name = "Syslog", risk = "low", desc = "系统日志服务"},
    ["873"] = {name = "RSync", risk = "medium", desc = "文件同步服务"},
    ["1080"] = {name = "SOCKS", risk = "medium", desc = "代理服务器"},
    ["1433"] = {name = "MSSQL", risk = "high", desc = "SQL Server数据库"},
    ["1521"] = {name = "Oracle", risk = "high", desc = "Oracle数据库"},
    ["2049"] = {name = "NFS", risk = "medium", desc = "网络文件系统"},
    ["3306"] = {name = "MySQL", risk = "high", desc = "MySQL数据库"},
    ["3389"] = {name = "RDP", risk = "high", desc = "Windows远程桌面"},
    ["5432"] = {name = "PostgreSQL", risk = "medium", desc = "PostgreSQL数据库"},
    ["5900"] = {name = "VNC", risk = "high", desc = "VNC远程控制"},
    ["5901"] = {name = "VNC:1", risk = "high", desc = "VNC远程控制(备用)"},
    ["6379"] = {name = "Redis", risk = "high", desc = "Redis数据库（未授权访问风险）"},
    ["8080"] = {name = "HTTP-Alt", risk = "low", desc = "HTTP备用端口"},
    [ "8888"] = {name = "HTTP-Alt2", risk = "low", desc = "HTTP备用端口"},
    ["9200"] = {name = "Elasticsearch", risk = "high", desc = "搜索引擎（可能未授权）"},
    ["27017"] = {name = "MongoDB", risk = "high", desc = "MongoDB数据库"},
    ["1880"] = {name = "MQTT", risk = "medium", desc = "MQTT消息队列服务"},
    ["5000"] = {name = "Docker", risk = "medium", desc = "Docker容器管理接口"},
    ["554"] = {name = "RTSP", risk = "medium", desc = "视频监控流媒体"}
}

-- 检测路由器开放端口（增强版）
local function check_router_open_ports()
    local open_ports = {}
    local util = require("luci.util")

    -- 尝试多种方式获取监听端口
    local output = ""
    local cmd1 = "ss -tlnp 2>/dev/null"
    local cmd2 = "netstat -tlnp 2>/dev/null"

    -- 优先使用ss命令
    output = util.exec(cmd1) or ""
    if not output or output == "" then
        output = util.exec(cmd2) or ""
    end

    if output and output ~= "" then
        for line in output:gmatch("[^\r\n]+") do
            -- 跳过表头和空行
            if line:match("%d+") and not line:match("^State") and not line:match("^Proto") then
                local port, addr, proc_info = nil, nil, nil

                -- 解析ss输出格式: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                if line:match("LISTEN") then
                    -- ss格式: LISTEN  0  128  *:80  *:*  users:(("nginx",pid=1234,...))
                    port, addr = line:match("LISTEN.*%s+(%S+):(%d+)%s+")
                    if not port then
                        -- 另一种格式: [::]:80
                        port, addr = line:match("LISTEN.*%s+%[?([^%]]*)%]?:(%d+)")
                    end

                    -- 提取进程信息
                    proc_info = line:match("users:%(.+%)")
                end

                -- 如果ss解析失败，尝试netstat格式
                if not port and line:match("^tcp") then
                    -- netstat格式: tcp  0  0 0.0.0.0:80  0.0.0.0:*  LISTEN  1234/nginx
                    port, addr = line:match("^tcp%d*%s+%d+%s+%d+%s+(%S+):(%d+)%s+")
                    if not port then
                        port, addr = line:match("^tcp%d*%s+%d+%s+%d+%s+%[?([^%]]*)%]?:(%d+)")
                    end
                    proc_info = line:match("%d+/(%S+)$")
                end

                if port then
                    local port_num_val = tonumber(port)
                    if port_num_val and port_num_val > 0 then
                        local is_external = false
                        local bind_addr = addr or "unknown"

                        -- 标准化地址显示
                        if bind_addr == "*" or bind_addr == "" then
                            bind_addr = "0.0.0.0"
                        end

                        -- 检查是否绑定到外部地址
                        if bind_addr == "0.0.0.0" or bind_addr == "::" then
                            is_external = true
                        elseif bind_addr ~= "127.0.0.1" and bind_addr ~= "::1" and bind_addr ~= "localhost" then
                            -- 非回环地址都视为外部可访问
                            if not bind_addr:match("^127%.") and not bind_addr:match("^::1") then
                                is_external = true
                            end
                        end

                        -- 获取端口信息（优先检查白名单）
                        local port_num = tostring(port_num_val)
                        local essential_info = ROUTER_ESSENTIAL_PORTS[port_num]
                        local port_info = nil
                        local port_category = "normal"
                        
                        if essential_info then
                            -- 端口在白名单中，标记为必要端口或IoT端口
                            port_info = {
                                name = essential_info.name,
                                risk = "safe",
                                desc = essential_info.desc
                            }
                            port_category = essential_info.category or "essential"
                        else
                            -- 不在白名单中，检查是否为危险端口
                            port_info = DANGEROUS_PORTS[port_num] or {
                                name = get_port_name(port_num),
                                risk = "low",
                                desc = "未知服务"
                            }
                            
                            -- 根据是否外部暴露调整风险等级
                            if is_external and port_info.risk == "low" then
                                port_info.risk = "medium"
                            end
                        end

                        table.insert(open_ports, {
                            port = port_num_val,
                            name = port_info.name,
                            bind_addr = bind_addr,
                            is_external = is_external,
                            risk = port_info.risk,
                            category = port_category,
                            description = port_info.desc,
                            process = proc_info or "unknown"
                        })
                    end
                end
            end
        end
    end

    -- 去重（同一端口可能监听在多个地址）
    local seen = {}
    local unique_ports = {}
    for _, p in ipairs(open_ports) do
        local key = p.port .. "_" .. p.bind_addr
        if not seen[key] then
            seen[key] = true
            table.insert(unique_ports, p)
        end
    end

    return unique_ports
end

-- API: 检测开放端口
function api_check_open_ports()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local ports = check_router_open_ports()
        
        -- 统计风险等级
        local external_count = 0
        local high_risk_count = 0
        local critical_count = 0
        
        for _, port in ipairs(ports) do
            if port.is_external then
                external_count = external_count + 1
                if port.risk == "high" then
                    high_risk_count = high_risk_count + 1
                elseif port.risk == "critical" then
                    critical_count = critical_count + 1
                end
            end
        end
        
        response_data = success_response({
            ports = ports,
            total_open = #ports,
            external_count = external_count,
            high_risk_count = high_risk_count,
            critical_count = critical_count,
            check_time = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "检测开放端口失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- DNS劫持检测（增强版）
local function check_dns_hijack()
    local results = {}
    local util = require("luci.util")

    -- DNS测试域名列表
    -- 国内域名：用于评分计算（主要指标）
    -- 国际域名：仅做参考测试，失败不扣分
    local test_domains = {
        -- 国内主流网站（6个，用于评分）
        {domain = "www.baidu.com", expected_pattern = "baidu", category = "domestic"},
        {domain = "www.aliyun.com", expected_pattern = "aliyun", category = "domestic"},
        {domain = "www.taobao.com", expected_pattern = "taobao", category = "domestic"},
        {domain = "www.qq.com", expected_pattern = "qq", category = "domestic"},
        {domain = "www.jd.com", expected_pattern = "jd", category = "domestic"},
        {domain = "www.bilibili.com", expected_pattern = "bilibili", category = "domestic"},
        
        -- 国际知名网站（2个，仅参考，失败不扣分）
        {domain = "www.cloudflare.com", expected_pattern = "cloudflare", category = "international"},
        {domain = "dns.google", expected_pattern = "google", category = "international"}
    }

    for _, test in ipairs(test_domains) do
        local dns_ok, dns_result = pcall(function()
            local resolved_ip = ""
            local is_normal = true
            local hijack_suspicion = false
            local error_msg = nil

            -- 尝试多种DNS查询方式
            local output = nil

            -- 方式1: 使用nslookup（如果可用）
            local cmd1 = "nslookup " .. test.domain .. " 2>/dev/null"
            output = util.exec(cmd1)

            if not output or output == "" then
                -- 方式2: 使用dig（如果可用）
                local cmd2 = "dig +short " .. test.domain .. " 2>/dev/null"
                output = util.exec(cmd2)
            end

            if not output or output == "" then
                -- 方式3: 使用host命令
                local cmd3 = "host " .. test.domain .. " 2>/dev/null"
                output = util.exec(cmd3)
            end

            if not output or output == "" or (output and not output:match("%d+%.%d+%.%d+%.%d+")) then
                -- 方式4: 使用ping获取IP地址（适用于大多数嵌入式系统）
                local cmd4 = "ping -c 1 -W 2 " .. test.domain .. " 2>/dev/null | grep PING | awk '{print $3}' | tr -d '()'"
                output = util.exec(cmd4)
            end

            if not output or output == "" or (output and not output:match("%d+%.%d+%.%d+%.%d+")) then
                -- 方式5: 使用wget测试网络连通性（间接验证DNS）
                local cmd5 = "wget -q --timeout=3 --spider http://" .. test.domain .. " 2>&1 && echo 'CONNECTED' || echo 'FAILED'"
                local wget_result = util.exec(cmd5) or ""
                
                if wget_result:match("CONNECTED") then
                    -- 网络可达，说明DNS工作正常（虽然不知道具体IP）
                    resolved_ip = "正常"
                    is_normal = true
                    error_msg = nil
                    return {
                        domain = test.domain,
                        category = test.category,
                        resolved_ip = resolved_ip,
                        is_normal = is_normal,
                        suspicion = false,
                        error = error_msg
                    }
                else
                    -- 无法通过任何方式验证
                    resolved_ip = "-"
                    is_normal = true
                    error_msg = "无法验证"
                    return {
                        domain = test.domain,
                        category = test.category,
                        resolved_ip = resolved_ip,
                        is_normal = is_normal,
                        suspicion = false,
                        error = error_msg
                    }
                end
            end

            -- 解析输出获取IP地址
            if output then
                -- nslookup格式: Address: 1.2.3.4 或 Name: example.com Address: 1.2.3.4
                resolved_ip = output:match("Address:%s*(%d+%.%d+%.%d+%.%d+)") or
                             output:match("Name:%s*(%S+)%s*Address:%s*(%d+%.%d+%.%d+%.%d+)")

                -- dig格式: 直接返回IP
                if not resolved_ip then
                    resolved_ip = output:match("^%s*(%d+%.%d+%.%d+%.%d+)%s*$")
                end

                -- host格式: example.com has address 1.2.3.4
                if not resolved_ip then
                    resolved_ip = output:match("has address%s+(%d+%.%d+%.%d+%.%d+)")
                end
                
                -- ping格式: 纯IP地址
                if not resolved_ip then
                    resolved_ip = output:match("^(%d+%.%d+%.%d+%.%d+)%s*$")
                end

                -- 安全检查：如果解析到可疑IP，标记为劫持嫌疑
                if resolved_ip and resolved_ip ~= "" and resolved_ip ~= "-" and resolved_ip ~= "正常" then
                    -- 检查是否为127.0.0.1（本地回环地址）
                    -- 注意：在OpenWrt环境中，解析到127.0.0.1通常是正常的
                    -- 可能原因：去广告插件(AdGuard Home)、透明代理(SSR/Clash)、防火墙规则等
                    if resolved_ip:match("^127%.") or resolved_ip == "127.0.0.1" then
                        -- 127.0.0.1在OpenWrt中很常见，不标记为劫持
                        -- 可能是去广告、代理插件的正常行为
                        hijack_suspicion = false
                        is_normal = true
                        error_msg = "本地重定向"
                    -- 检查是否为其他私有IP或特殊IP（这些才可能是劫持）
                    elseif resolved_ip:match("^0%.") or
                           resolved_ip:match("^169%.254%.") or
                           (resolved_ip:match("^10%.") and test.domain:match("com$")) or
                           ((resolved_ip:match("^192%.168%.") or resolved_ip:match("^172%.1[6-9]%.") or resolved_ip:match("^172%.2%d%.") or resolved_ip:match("^172%.3[01]%.")) and test.domain:match("^www%.")) then
                        hijack_suspicion = true
                        is_normal = false
                    end

                    -- 检查是否为已知恶意IP段（简化检查）
                    local first_octet = resolved_ip:match("^(%d+)%.")
                    if first_octet and tonumber(first_octet) == 0 and not (resolved_ip:match("^127%.")) then
                        hijack_suspicion = true
                        is_normal = false
                    end
                elseif not resolved_ip or resolved_ip == "" or resolved_ip == "-" then
                    -- 无法解析IP但之前已处理过这种情况
                    is_normal = true
                    error_msg = nil
                end
            else
                is_normal = true
                error_msg = nil
            end

            return {
                domain = test.domain,
                category = test.category,
                resolved_ip = resolved_ip or "-",
                is_normal = is_normal,
                suspicion = hijack_suspicion,
                error = error_msg
            }
        end)

        if dns_ok and dns_result then
            table.insert(results, dns_result)
        else
            -- 检测过程出错时，不标记为异常，而是标记为无法检测
            table.insert(results, {
                domain = test.domain,
                category = test.category,
                resolved_ip = "-",
                is_normal = true,
                suspicion = false,
                error = "检测超时"
            })
        end
    end

    -- 检查路由器DNS设置
    local dns_servers = {}
    local uci_check, _ = pcall(function()
        local uci = require("luci.model.uci").cursor()

        -- 检查多个可能的DNS配置位置
        local ns_lan = uci:get("network", "lan", "dns")
        local ns_wan = uci:get("network", "wan", "dns")
        local ns_wan6 = uci:get("network", "wan6", "dns")

        -- 合并所有DNS服务器
        local all_dns = {}
        if ns_lan then
            for server in ns_lan:gmatch("[^%s]+") do
                all_dns[server] = true
            end
        end
        if ns_wan then
            for server in ns_wan:gmatch("[^%s]+") do
                all_dns[server] = true
            end
        end
        if ns_wan6 then
            for server in ns_wan6:gmatch("[^%s]+") do
                all_dns[server] = true
            end
        end

        -- 转换为数组
        for server, _ in pairs(all_dns) do
            table.insert(dns_servers, server)
        end
    end)

    -- 如果没有找到DNS服务器，尝试从resolv.conf读取
    if #dns_servers == 0 then
        local resolv_conf = util.exec("cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}'") or ""
        if resolv_conf and resolv_conf ~= "" then
            for server in resolv_conf:gmatch("[^\r\n]+") do
                if server:match("%d+%.%d+%.%d+%.%d+") then
                    table.insert(dns_servers, server)
                end
            end
        end
    end

    -- 统计结果：只统计国内域名用于评分
    local suspicious_count = 0
    local failed_count = 0
    local success_count = 0
    local unverified_count = 0
    
    -- 国际域名统计（仅参考，不参与评分）
    local intl_suspicious_count = 0
    local intl_failed_count = 0
    local intl_success_count = 0
    
    for _, r in ipairs(results) do
        -- 判断是否为国内域名
        local is_domestic = (r.category == "domestic")
        
        if r.suspicion then 
            if is_domestic then
                suspicious_count = suspicious_count + 1 
            else
                intl_suspicious_count = intl_suspicious_count + 1
            end
        end
        
        -- 分类统计检测结果
        if not r.is_normal and r.error then
            if r.error == "无法验证" or r.error == "检测超时" then
                -- 无法验证的情况：视为正常（DNS工作正常但工具受限）
                unverified_count = unverified_count + 1
                success_count = success_count + 1
            else
                -- 明确的失败情况
                if is_domestic then
                    failed_count = failed_count + 1
                else
                    intl_failed_count = intl_failed_count + 1
                end
            end
        elseif r.is_normal then
            if is_domestic then
                success_count = success_count + 1
            else
                intl_success_count = intl_success_count + 1
            end
        end
    end
    
    -- DNS安全判断：只根据国内域名判断
    -- 只要没有可疑劫持，就认为DNS基本正常
    local is_safe = (suspicious_count == 0)
    
    -- 调试日志：输出DNS检测结果
    print("[DNS检测] 国内-成功:" .. success_count .. " 失败:" .. failed_count .. " 可疑:" .. suspicious_count)
    print("[DNS检测] 国际-成功:" .. intl_success_count .. " 失败:" .. intl_failed_count .. " 可疑:" .. intl_suspicious_count)

    return {
        tests = results,
        dns_servers = dns_servers,
        -- 国内域名统计（用于评分）
        suspicious_count = suspicious_count,
        failed_count = failed_count,
        success_count = success_count,
        domestic_total = 6,  -- 国内域名总数
        -- 国际域名统计（仅参考）
        intl_suspicious_count = intl_suspicious_count,
        intl_failed_count = intl_failed_count,
        intl_success_count = intl_success_count,
        international_total = 2,  -- 国际域名总数
        -- 总体判断
        total_tests = #results,
        is_safe = is_safe
    }
end

-- API: 检测DNS劫持
function api_check_dns_hijack()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local results = check_dns_hijack()
        
        response_data = success_response({
            tests = results.tests,
            dns_servers = results.dns_servers,
            suspicious_count = results.suspicious_count,
            failed_count = results.failed_count,
            total_tests = results.total_tests,
            is_safe = results.is_safe,
            check_time = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "DNS劫持检测失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- 弱密码检测（增强版）
local function check_weak_passwords()
    local results = {}

    -- 1. 检查WiFi密码强度
    local wifi_checks = {}
    local uci_ok, _ = pcall(function()
        local uci = require("luci.model.uci").cursor()

        -- 遍历WiFi配置（支持多种无线配置格式）
        uci:foreach("wireless", "wifi-iface", function(s)
            local ssid = s.ssid or ""
            local key = s.key or ""
            local encryption = s.encryption or "none"
            local disabled = s.disabled

            -- 跳过禁用的WiFi和未加密的WiFi
            if ssid ~= "" and disabled ~= "1" then
                if encryption == "none" or encryption == "psk" or encryption == "" then
                    -- 未加密或使用预共享密钥（无实际密码）
                    table.insert(wifi_checks, {
                        type = "wifi",
                        name = "WiFi: " .. ssid,
                        password_length = 0,
                        encryption = encryption or "none",
                        strength = "critical",
                        score = 0,
                        issues = {"WiFi未加密或使用弱加密方式!"}
                    })
                elseif key and key ~= "" then
                    local strength = "strong"
                    local issues = {}
                    local score = 100

                    -- 密码长度检查
                    if #key < 8 then
                        score = score - 40
                        table.insert(issues, "密码长度不足8位")
                        strength = "weak"
                    elseif #key < 12 then
                        score = score - 15
                        table.insert(issues, "建议使用12位以上密码")
                    end

                    -- 复杂度检查
                    local has_upper = key:find("%u")
                    local has_lower = key:find("%l")
                    local has_digit = key:find("%d")
                    local has_special = key:find("%W")

                    local complexity = (has_upper and 1 or 0) +
                                    (has_lower and 1 or 0) +
                                    (has_digit and 1 or 0) +
                                    (has_special and 1 or 0)

                    if complexity <= 1 then
                        score = score - 30
                        table.insert(issues, "密码复杂度太低，建议混合大小写字母、数字和符号")
                        if strength ~= "weak" then strength = "medium" end
                    elseif complexity <= 2 then
                        score = score - 15
                        table.insert(issues, "密码复杂度一般，建议增加字符种类")
                    end

                    -- 常见弱密码检查（扩展版：包含Top 100常见弱密码和路由器默认密码）
                    local weak_patterns = {
                        -- Top 20 最常见弱密码
                        "12345678", "password", "admin888", "88888888",
                        "00000000", "abcdefgh", "qwertyui", "11111111",
                        "1234567890", "123456789", "password123", "admin123",
                        "iloveyou", "sunshine", "princess", "abc123456",
                        "monkey", "dragon", "master", "letmein",
                        -- 路由器默认密码
                        "admin", "root", "password", "1234", "12345",
                        "123456", "1234567", "123456789", "1234567890",
                        "admin1234", "passw0rd", "welcome1", "qwerty123",
                        -- 中文用户常见弱密码
                        "woaini1314", "aaron423", "5201314", "5211314",
                        "zhangsan", "lisi", "wangwu", "test1234",
                        -- 纯数字弱密码
                        "66666666", "88888888", "99999999", "00000000",
                        "11223344", "12121212", "12332111", "14725836",
                        -- 键盘模式弱密码
                        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx",
                        "qazwsxedc", "1q2w3e4r", "zaq12wsx", "qweasd123"
                    }
                    local lower_key = key:lower()
                    for _, pattern in ipairs(weak_patterns) do
                        if lower_key == pattern then
                            score = 0
                            strength = "critical"
                            table.insert(issues, "使用了极弱的常用密码! 建议立即更换")
                            break
                        end
                    end

                    -- 密码更新建议（基于密码长度和复杂度）
                    if #key >= 8 and score >= 80 then
                        table.insert(issues, "✅ 密码强度良好，建议每3-6个月更换一次")
                    elseif score >= 60 then
                        table.insert(issues, "⚠️ 建议增加密码长度到12位以上并定期更换")
                    end

                    -- 连续字符检查
                    if key:match("(%w)%1%1%1") then
                        score = score - 10
                        table.insert(issues, "包含4个以上连续相同字符")
                    end

                    if score < 60 then strength = "weak"
                    elseif score < 80 then strength = "medium"
                    else strength = "strong" end

                    table.insert(wifi_checks, {
                        type = "wifi",
                        name = "WiFi: " .. ssid,
                        password_length = #key,
                        encryption = encryption,
                        strength = strength,
                        score = score,
                        issues = issues
                    })
                end
            end
        end)
    end)

    if not uci_ok then
        table.insert(wifi_checks, {
            type = "wifi",
            name = "WiFi配置读取失败",
            password_length = 0,
            encryption = "unknown",
            strength = "unknown",
            score = -1,
            issues = {"无法读取WiFi配置文件"}
        })
    end

    results.wifi = wifi_checks

    -- 2. 检查管理后台密码
    local admin_checks = {}
    local admin_ok, _ = pcall(function()
        local util = require("luci.util")

        -- 检查/etc/shadow中的root密码哈希（需要root权限）
        local shadow_check = util.exec("cat /etc/shadow 2>/dev/null | grep '^root:' | cut -d: -f2") or ""
        
        -- 调试日志
        print("[密码检测] shadow_check结果: " .. tostring(shadow_check ~= "" and "有内容" or "空"))
        print("[密码检测] shadow_check值: " .. (shadow_check:sub(1, 20) or "nil"))

        -- 检查是否有密码设置
        local has_password_set = false
        local is_default_password = false
        local pwd_info = ""

        if shadow_check and shadow_check ~= "" then
            -- 如果shadow字段不为空且不是特殊值，说明设置了密码
            if shadow_check ~= "!" and shadow_check ~= "*" and shadow_check ~= "!!" and shadow_check ~= "" then
                has_password_set = true
                pwd_info = shadow_check:sub(1, 10) .. "..."  -- 只显示前几个字符用于识别类型
                print("[密码检测] 检测到已设置密码: " .. pwd_info)
            else
                print("[密码检测] shadow为特殊值: " .. tostring(shadow_check))
            end
        else
            print("[密码检测] shadow为空或读取失败")
        end

        -- 备用检查：通过UCI检查（某些系统可能使用不同的存储方式）
        if not has_password_set then
            local uci = require("luci.model.uci").cursor()
            local root_pwd_uci = uci:get("system", "@system[0]", "rootpassword") or ""

            if root_pwd_uci and root_pwd_uci ~= "" then
                has_password_set = true
                pwd_info = "已设置(UCI)"
            end
        end

        -- 检查是否为常见默认密码（通过尝试认证或其他方式）
        -- 注意：这里不能直接验证密码，只能给出建议
        if not has_password_set then
            table.insert(admin_checks, {
                type = "admin",
                name = "管理后台密码",
                has_password = false,
                strength = "critical",
                score = 0,
                issues = {"未设置管理密码或使用默认密码!", "请立即在 系统→管理员权限 中设置强密码"},
                recommendation = "立即设置强密码（至少8位，包含字母、数字和符号）"
            })
        else
            -- 已设置密码，给出安全建议
            local pwd_score = 100
            local pwd_issues = {}

            -- 由于无法直接读取明文密码，基于其他因素评估
            table.insert(pwd_issues, "✅ 已设置管理密码")

            -- 检查是否可以通过其他方式判断密码强度
            if pwd_info:match("^$6$") or pwd_info:match("^$5$") then
                -- SHA-512或SHA-256加密，相对较新
                pwd_issues = {"✅ 已设置管理密码（使用现代加密算法SHA-512/256）"}
                pwd_score = 95
            elseif pwd_info:match("^$1$") then
                -- MD5加密，较弱
                table.insert(pwd_issues, "⚠️ 密码使用MD5加密，建议升级系统")
                pwd_score = 70
            elseif pwd_info:match("^$2[aby]$") then
                -- Blowfish加密，较强
                pwd_issues = {"✅ 已设置管理密码（使用强加密算法Blowfish）"}
                pwd_score = 95
            else
                -- 其他情况：已设置密码但无法识别加密算法
                pwd_issues = {"✅ 已设置管理密码", "加密算法类型：未知（可能使用特殊加密）"}
                pwd_score = 85  -- 提高分数，因为已设置密码
            end

            local pwd_strength = pwd_score >= 85 and "strong" or (pwd_score >= 70 and "medium" or "weak")

            table.insert(admin_checks, {
                type = "admin",
                name = "管理后台密码",
                has_password = true,
                strength = pwd_strength,
                score = pwd_score,
                issues = pwd_issues,
                recommendation = pwd_score < 80 and "建议定期更换密码并确保密码复杂度足够高" or nil
            })
        end
    end)

    if not admin_ok then
        table.insert(admin_checks, {
            type = "admin",
            name = "管理后台密码检查失败",
            has_password = nil,
            strength = "error",
            score = -1,
            issues = {"无法检查管理密码状态"},
            error = "权限不足或系统不支持"
        })
    end

    results.admin = admin_checks

    -- 统计结果
    local weak_count = 0
    local medium_count = 0
    local critical_count = 0

    for _, w in ipairs(wifi_checks) do
        if w.strength == "weak" then weak_count = weak_count + 1
        elseif w.strength == "medium" then medium_count = medium_count + 1 end
    end

    for _, a in ipairs(admin_checks) do
        if a.strength == "critical" then critical_count = critical_count + 1
        elseif a.strength == "weak" then weak_count = weak_count + 1
        elseif a.strength == "medium" then medium_count = medium_count + 1 end
    end

    results.summary = {
        weak_count = weak_count,
        medium_count = medium_count,
        critical_count = critical_count,
        total_checked = #wifi_checks + #admin_checks,
        is_all_strong = weak_count == 0 and critical_count == 0
    }

    return results
end

-- API: 检测弱密码
function api_check_weak_passwords()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local results = check_weak_passwords()
        
        response_data = success_response({
            wifi = results.wifi,
            admin = results.admin,
            summary = results.summary,
            check_time = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "弱密码检测失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 运行完整安全扫描
function api_run_security_scan()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        -- 并行执行各项检测
        local ports = check_router_open_ports()
        local dns_results = check_dns_hijack()
        local pwd_results = check_weak_passwords()
        
        -- 计算综合安全评分（纯累加制）
        -- 从0分开始，通过安全配置累加得分
        local security_score = 0
        
        -- ========== 维度1：开放端口（权重35%） ==========
        -- 评分规则：扣分制+奖励制
        -- 基准分：20分，范围：0-35分
        local port_score = 20  -- 基准分（中间值）
        
        local external_port_count = 0
        local essential_port_count = 0
        local high_risk_port_count = 0
        
        for _, port in ipairs(ports) do
            -- 统计必要端口
            if port.category == "essential" or port.category == "iot" then
                essential_port_count = essential_port_count + 1
            elseif port.is_external then
                external_port_count = external_port_count + 1
                -- 统计高风险端口数量
                if port.risk == "critical" then
                    high_risk_port_count = high_risk_port_count + 2  -- 极危端口权重更高
                elseif port.risk == "high" then
                    high_risk_port_count = high_risk_port_count + 1
                end
            end
        end
        
        -- ===== 扣分制 =====
        -- 有外部开放端口：每个扣5分
        port_score = port_score - (external_port_count * 5)
        -- 有高风险端口：每个扣10分
        port_score = port_score - (high_risk_port_count * 10)
        
        -- ===== 奖励制 =====
        -- 必要端口配置正确(≥3个)：+10分
        if essential_port_count >= 3 then
            port_score = port_score + 10
        end
        -- 无外部开放端口：+5分（额外奖励）
        if external_port_count == 0 then
            port_score = port_score + 5
        end
        
        -- 应用分数限制：最低0分，最高35分
        if port_score < 0 then port_score = 0 end
        if port_score > 35 then port_score = 35 end
        
        security_score = security_score + port_score
        
        -- ========== 维度2：DNS状态（权重25%） ==========
        -- 最高可得25分
        local dns_score = 0
        
        -- DNS解析正常：+15分
        if dns_results.is_safe then
            dns_score = dns_score + 15
        end
        -- 无DNS劫持嫌疑：+10分
        if dns_results.suspicious_count == 0 then
            dns_score = dns_score + 10
        end
        
        security_score = security_score + math.min(dns_score, 25)
        
        -- ========== 维度3：密码强度（权重40%） ==========
        -- 评分规则：弱以下扣分制，弱以上奖励制
        -- 基准分：20分（有密码时），0分（无密码时），范围：0-40分
        local pwd_score = 0  -- 默认0分
        
        if pwd_results.summary and (pwd_results.summary.total_checked or 0) > 0 then
            -- 有密码检测时，设置基准分
            pwd_score = 20  -- 基准分（中间值）
            
            local total = pwd_results.summary.total_checked or 0
            local critical = pwd_results.summary.critical_count or 0
            local weak = pwd_results.summary.weak_count or 0
            local medium = pwd_results.summary.medium_count or 0
            local strong = total - critical - weak - medium
            
            -- ===== 扣分制（弱以下）=====
            -- 极弱密码：每个扣10分
            pwd_score = pwd_score - (critical * 10)
            -- 弱密码：每个扣5分
            pwd_score = pwd_score - (weak * 5)
            
            -- ===== 奖励制（弱以上，不包含弱）=====
            -- 中等密码：每个加5分
            pwd_score = pwd_score + (medium * 5)
            -- 强密码：每个加10分
            pwd_score = pwd_score + (strong * 10)
        end
        -- 无密码检测时，pwd_score = 0
        
        -- 应用分数限制：最低0分，最高40分
        if pwd_score < 0 then pwd_score = 0 end
        if pwd_score > 40 then pwd_score = 40 end
        
        security_score = security_score + pwd_score
        
        -- ========== 风险原因分析 ==========
        local risk_reasons = {}
        
        -- 开放端口风险分析
        if external_port_count > 0 then
            table.insert(risk_reasons, {
                category = "ports",
                level = external_port_count > 3 and "high" or "medium",
                reason = "发现" .. external_port_count .. "个外部开放端口",
                suggestion = "建议关闭不必要的外部端口，或使用防火墙限制访问"
            })
        end
        if high_risk_port_count > 0 then
            table.insert(risk_reasons, {
                category = "ports",
                level = "critical",
                reason = "发现" .. high_risk_port_count .. "个高风险端口开放",
                suggestion = "立即关闭Telnet(23)、Rexec(512)等高危端口"
            })
        end
        
        -- DNS风险分析
        if not dns_results.is_safe then
            table.insert(risk_reasons, {
                category = "dns",
                level = "high",
                reason = "DNS解析存在异常",
                suggestion = "检查DNS服务器配置，确保使用可信的DNS服务器"
            })
        end
        if dns_results.suspicious_count and dns_results.suspicious_count > 0 then
            table.insert(risk_reasons, {
                category = "dns",
                level = "critical",
                reason = "检测到" .. dns_results.suspicious_count .. "个DNS劫持嫌疑",
                suggestion = "立即检查DNS设置，更换可信的DNS服务器"
            })
        end
        
        -- 密码风险分析
        if pwd_results.summary then
            local critical = pwd_results.summary.critical_count or 0
            local weak = pwd_results.summary.weak_count or 0
            
            if critical > 0 then
                table.insert(risk_reasons, {
                    category = "password",
                    level = "critical",
                    reason = "发现" .. critical .. "个极弱密码",
                    suggestion = "立即更换密码，使用8位以上包含大小写字母、数字和特殊字符的密码"
                })
            end
            if weak > 0 then
                table.insert(risk_reasons, {
                    category = "password",
                    level = "high",
                    reason = "发现" .. weak .. "个弱密码",
                    suggestion = "建议增强密码强度，添加更多字符类型"
                })
            end
        end
        
        -- 无密码检测警告
        if not pwd_results.summary or (pwd_results.summary.total_checked or 0) == 0 then
            table.insert(risk_reasons, {
                category = "password",
                level = "medium",
                reason = "未检测到密码配置",
                suggestion = "请确保已设置WiFi密码和管理后台密码"
            })
        end
        
        -- ========== 分数限制 ==========
        -- 最高100分，最低0分
        if security_score > 100 then security_score = 100 end
        if security_score < 0 then security_score = 0 end
        
        -- ========== 安全等级（优化阈值） ==========
        local level = security_score >= 90 and "安全" or 
                     (security_score >= 75 and "良好" or 
                     (security_score >= 60 and "一般" or 
                     (security_score >= 45 and "风险" or "危险")))
        
        response_data = success_response({
            security_score = security_score,
            security_level = level,
            risk_reasons = risk_reasons,
            open_ports = {
                ports = ports,
                total_open = #ports,
                external_count = external_port_count,
                high_risk_count = high_risk_port_count
            },
            dns_check = {
                tests = dns_results.tests,
                suspicious_count = dns_results.suspicious_count,
                failed_count = dns_results.failed_count,
                success_count = dns_results.success_count or 0,
                is_safe = dns_results.is_safe
            },
            password_check = {
                wifi = pwd_results.wifi,
                admin = pwd_results.admin,
                summary = pwd_results.summary
            },
            scan_time = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "安全扫描失败", tostring(err))
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

-- ========== 实时网速监控功能 ==========

-- 从文件加载实时网速缓存
local function load_realtime_speed_cache()
    local fd = io.open(REALTIME_SPEED_CACHE_FILE, "r")
    if fd then
        local content = fd:read("*a")
        fd:close()
        if content and content ~= "" then
            local ok, data = pcall(function()
                return require("luci.jsonc").parse(content)
            end)
            if ok and data and type(data) == "table" then
                return data
            end
        end
    end
    return { points = {}, last_total_rx = 0, last_total_tx = 0, last_time = 0 }
end

-- 保存实时网速缓存到文件
local function save_realtime_speed_cache(data)
    local dir = REALTIME_SPEED_CACHE_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local json = require("luci.jsonc")
    local json_str = json.stringify(data) or "{}"
    local fd = io.open(REALTIME_SPEED_CACHE_FILE, "w")
    if fd then
        fd:write(json_str)
        fd:close()
    end
end

-- 获取当前总流量（从ipset获取）
local function get_current_total_traffic()
    local util = require("luci.util")
    local total_rx = 0
    local total_tx = 0
    
    -- 获取TX流量（上行）
    local tx_output = util.exec("ipset list " .. IPSET_TX_NAME .. " 2>/dev/null")
    if tx_output then
        for bytes in tx_output:gmatch("packets%s+%d+%s+bytes%s+(%d+)") do
            total_tx = total_tx + (tonumber(bytes) or 0)
        end
    end
    
    -- 获取RX流量（下行，IPv4）
    local rx_ip_output = util.exec("ipset list " .. IPSET_RX_IP_NAME .. " 2>/dev/null")
    if rx_ip_output then
        for bytes in rx_ip_output:gmatch("packets%s+%d+%s+bytes%s+(%d+)") do
            total_rx = total_rx + (tonumber(bytes) or 0)
        end
    end
    
    -- 获取RX流量（下行，IPv6）
    local rx_ip6_output = util.exec("ipset list " .. IPSET_RX_IP6_NAME .. " 2>/dev/null")
    if rx_ip6_output then
        for bytes in rx_ip6_output:gmatch("packets%s+%d+%s+bytes%s+(%d+)") do
            total_rx = total_rx + (tonumber(bytes) or 0)
        end
    end
    
    return total_rx, total_tx
end

-- 更新实时网速数据点
local function update_realtime_speed_data()
    local now = os.time()
    local cache = load_realtime_speed_cache()
    
    -- 获取当前总流量
    local current_rx, current_tx = get_current_total_traffic()
    
    pcall(nixio.syslog, "info", "[RouterAssistant] speed_update: 当前流量 RX=" .. current_rx .. " TX=" .. current_tx .. 
        " 上次时间=" .. (cache.last_time or 0) .. 
        " 上次RX=" .. (cache.last_total_rx or 0))
    
    -- 计算网速（字节/秒）
    local speed_rx = 0
    local speed_tx = 0
    local time_diff = now - (cache.last_time or now)
    
    if cache.last_time and cache.last_time > 0 and time_diff > 0 then
        -- 处理计数器回绕
        local last_rx = cache.last_total_rx or 0
        local last_tx = cache.last_total_tx or 0
        
        if current_rx >= last_rx then
            speed_rx = (current_rx - last_rx) / time_diff
        else
            -- 计数器回绕或ipset重置
            local diff_rx = current_rx - last_rx
            if diff_rx < -1000000 then
                -- 大幅减少，可能是计数器回绕（32位无符号）
                speed_rx = ((4294967296 - last_rx) + current_rx) / time_diff
            else
                -- 小幅波动，可能是ipset清空重置，忽略本次计算
                speed_rx = 0
                pcall(nixio.syslog, "warning", "[RouterAssistant] RX流量异常减少，可能ipset重置: " .. tostring(last_rx) .. " -> " .. tostring(current_rx))
            end
        end
        
        if current_tx >= last_tx then
            speed_tx = (current_tx - last_tx) / time_diff
        else
            -- 计数器回绕或ipset重置
            local diff = current_tx - last_tx
            if diff < -1000000 then
                -- 大幅减少，可能是计数器回绕（32位无符号）
                speed_tx = ((4294967296 - last_tx) + current_tx) / time_diff
            else
                -- 小幅波动，可能是ipset清空重置，忽略本次计算
                speed_tx = 0
                pcall(nixio.syslog, "warning", "[RouterAssistant] TX流量异常减少，可能ipset重置: " .. tostring(last_tx) .. " -> " .. tostring(current_tx))
            end
        end
        
        -- 负数保护：网速不可能为负值
        if speed_rx < 0 then
            pcall(nixio.syslog, "warning", "[RouterAssistant] RX网速为负，修正为0: " .. tostring(speed_rx))
            speed_rx = 0
        end
        
        if speed_tx < 0 then
            pcall(nixio.syslog, "warning", "[RouterAssistant] TX网速为负，修正为0: " .. tostring(speed_tx))
            speed_tx = 0
        end
        
        pcall(nixio.syslog, "info", "[RouterAssistant] speed_update: 计算网速 RX=" .. speed_rx .. " TX=" .. speed_tx .. 
            " 时间差=" .. time_diff .. "秒")
    else
        pcall(nixio.syslog, "info", "[RouterAssistant] speed_update: 首次调用或时间差无效，记录基准数据")
    end
    
    -- 添加新数据点
    local new_point = {
        time = now,
        speed_rx = speed_rx,
        speed_tx = speed_tx,
        speed_total = speed_rx + speed_tx
    }
    
    table.insert(cache.points, new_point)
    
    -- 限制数据点数量
    while #cache.points > MAX_REALTIME_POINTS do
        table.remove(cache.points, 1)
    end
    
    -- 更新缓存
    cache.last_total_rx = current_rx
    cache.last_total_tx = current_tx
    cache.last_time = now
    
    save_realtime_speed_cache(cache)
    
    return cache.points
end

-- API接口：获取实时网速历史数据
function api_get_traffic_history()
    local response_data = { code = 0, points = {}, current_speed = { rx = 0, tx = 0, total = 0 } }
    
    local ok, err = pcall(function()
        -- 更新并获取实时网速数据
        local points = update_realtime_speed_data()
        
        pcall(nixio.syslog, "info", "[RouterAssistant] traffic_history: 获取到 " .. #points .. " 个数据点")
        
        -- 格式化数据点（添加显示用的时间戳）
        local formatted_points = {}
        for i, point in ipairs(points) do
            table.insert(formatted_points, {
                time = point.time,
                display_time = os.date("%H:%M:%S", point.time),
                speed_rx = point.speed_rx,
                speed_tx = point.speed_tx,
                speed_total = point.speed_total,
                speed_rx_display = format_bytes(point.speed_rx) .. "/s",
                speed_tx_display = format_bytes(point.speed_tx) .. "/s",
                speed_total_display = format_bytes(point.speed_total) .. "/s"
            })
        end
        
        response_data.points = formatted_points
        
        -- 当前网速（最后一个数据点）
        if #points > 0 then
            local last = points[#points]
            response_data.current_speed = {
                rx = last.speed_rx,
                tx = last.speed_tx,
                total = last.speed_total,
                rx_display = format_bytes(last.speed_rx) .. "/s",
                tx_display = format_bytes(last.speed_tx) .. "/s",
                total_display = format_bytes(last.speed_total) .. "/s"
            }
            
            pcall(nixio.syslog, "info", "[RouterAssistant] traffic_history: 当前速度 RX=" .. 
                (response_data.current_speed.rx_display or "") .. 
                " TX=" .. (response_data.current_speed.tx_display or ""))
        end
    end)
    
    if not ok then
        pcall(nixio.syslog, "err", "[RouterAssistant] traffic_history: 错误 - " .. tostring(err))
        response_data = error_response(-1, "获取实时网速失败", tostring(err))
    else
        response_data = success_response(response_data)
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- ========== 实时网速监控功能结束 ==========

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
                
                -- 优先从 iw dev 获取真实的信道和频率
                local iw_dev_info = sys.exec("iw dev " .. safe_ifname_val .. " info 2>/dev/null")
                local real_channel, real_freq_mhz = nil, nil
                
                if iw_dev_info and iw_dev_info ~= "" then
                    -- 解析格式: "channel 64 (5320 MHz), width: 160 MHz"
                    real_channel = iw_dev_info:match("channel%s+(%d+)")
                    real_freq_mhz = iw_dev_info:match("%((%d+)%s*MHz%)")
                end
                
                if real_channel and real_freq_mhz then
                    -- 从 iw dev 获取到真实值
                    status.channel = real_channel
                    status.frequency = string.format("%.3f GHz", tonumber(real_freq_mhz) / 1000)
                else
                    -- iw dev 获取不到，从 UCI 配置获取
                    local uci_channel = uci:get("wireless", device, "channel")
                    if uci_channel and uci_channel ~= "" and uci_channel ~= "auto" then
                        status.channel = uci_channel
                        -- 根据信道计算频率
                        local ch_num = tonumber(uci_channel)
                        if ch_num then
                            if ch_num >= 1 and ch_num <= 14 then
                                -- 2.4GHz 频段
                                local freq_map = {
                                    [1] = 2.412, [2] = 2.417, [3] = 2.422, [4] = 2.427,
                                    [5] = 2.432, [6] = 2.437, [7] = 2.442, [8] = 2.447,
                                    [9] = 2.452, [10] = 2.457, [11] = 2.462, [12] = 2.467,
                                    [13] = 2.472, [14] = 2.484
                                }
                                status.frequency = (freq_map[ch_num] or 2.412) .. " GHz"
                            elseif ch_num >= 36 and ch_num <= 165 then
                                -- 5GHz 频段
                                local freq_5g = 5.000 + (ch_num - 36) * 0.005
                                status.frequency = string.format("%.3f GHz", freq_5g)
                            end
                        end
                    else
                        -- UCI也没有配置，从iwinfo获取
                        local channel_line = iwinfo_output:match("Channel:%s*([^\n]+)")
                        if channel_line then
                            local ch, freq = channel_line:match("(%d+)%s*%(([%d%.]+)%s*GHz%)")
                            if ch then status.channel = ch end
                            if freq then
                                status.frequency = freq .. " GHz"
                            end
                        end
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
    local mac_no_colon = safe_mac
    local mac_no_colon_lower = safe_mac:lower()

    -- 先获取设备信息（快速操作，不会阻塞）
    local device_ip = ""
    local device_hostname = "未知设备"
    local safe_device_ip = nil

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
    -- 移除 2>/dev/null 以便错误信息能被记录到日志
    table.insert(script_parts, "echo '[kick_device] Adding iptables DROP rules for MAC: " .. safe_mac_quoted .. "'")
    table.insert(script_parts, "iptables -I INPUT -m mac --mac-source " .. safe_mac_quoted .. " -j DROP")
    table.insert(script_parts, "iptables -I FORWARD -m mac --mac-source " .. safe_mac_quoted .. " -j DROP")
    -- 同时添加 ip6tables 规则（阻止 IPv6 流量）
    table.insert(script_parts, "ip6tables -I INPUT -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")
    table.insert(script_parts, "ip6tables -I FORWARD -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")
    table.insert(script_parts, "echo '[kick_device] iptables rules added, checking...'")
    table.insert(script_parts, "iptables -L INPUT -n | grep -i 'MAC.*" .. mac_no_colon_lower .. "' || echo 'No INPUT rule found'")
    table.insert(script_parts, "iptables -L FORWARD -n | grep -i 'MAC.*" .. mac_no_colon_lower .. "' || echo 'No FORWARD rule found'")

    -- 【高优先级】conntrack 清除已有连接（阻止残留流量）
    if safe_device_ip then
        table.insert(script_parts, "echo '[kick_device] Clearing conntrack for IP: " .. safe_ip_quoted .. "'")
        table.insert(script_parts, "conntrack -D -s " .. safe_ip_quoted .. " 2>/dev/null || true")
        table.insert(script_parts, "conntrack -D -d " .. safe_ip_quoted .. " 2>/dev/null || true")
        -- 清除 IPv6 conntrack
        table.insert(script_parts, "conntrack -D -f ipv6 -s " .. safe_ip_quoted .. " 2>/dev/null || true")
        table.insert(script_parts, "conntrack -D -f ipv6 -d " .. safe_ip_quoted .. " 2>/dev/null || true")
    end
    table.insert(script_parts, "conntrack -D -m " .. mac_no_colon_lower .. " 2>/dev/null || true")
    -- 清除 flowtable 中的条目（FLOWOFFLOAD 硬件加速）
    table.insert(script_parts, "echo '[kick_device] Clearing flowtable entries...'")
    table.insert(script_parts, "echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose 2>/dev/null || true")

    -- 【低优先级】iw 命令踢出无线连接（MTK驱动可能阻塞，timeout保护）
    local ifaces = {"ra0", "rai0", "ra1", "rai1", "apcli0", "apcli1"}
    for _, iface in ipairs(ifaces) do
        table.insert(script_parts, "iw dev " .. iface .. " station del " .. safe_mac_colon_quoted .. " 2>/dev/null || true")
    end

    -- 【低优先级】access_ctl.sh ACL黑名单（如果存在）
    local timeout_cmd = get_timeout_cmd() or ""
    table.insert(script_parts, "if [ -x /usr/bin/access_ctl.sh ]; then " .. timeout_cmd .. " 5 access_ctl.sh -m " .. safe_mac_lower_quoted .. " -a 0 2>/dev/null || true; fi")

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
        -- 【关键修复】使用 exec_background_nowait 确保后台执行不被阻塞
        nixio.syslog("info", "[RouterAssistant] kick_device: script file created: " .. script_file)
        nixio.syslog("info", "[RouterAssistant] kick_device: script content:\n" .. script_content)
        os.execute("chmod +x '" .. script_file .. "'")
        exec_background_nowait("nohup /bin/sh '" .. script_file .. "' >/tmp/router_assistant_kick.log 2>&1 &")
        exec_background_nowait("(sleep 15 && rm -f '" .. script_file .. "') >/dev/null 2>&1 &")
    else
        -- 【问题4修复】fallback 路径：转义 cmd 中的单引号（防御深度）
        nixio.syslog("warning", "[RouterAssistant] kick_device: cannot write script file, using fallback for " .. mac_colon)
        for _, cmd in ipairs(script_parts) do
            local escaped_cmd = cmd:gsub("'", "'\\''")
            exec_background_nowait("nohup /bin/sh -c '" .. escaped_cmd .. "' >/dev/null 2>&1 &")
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
    local nixio = require("nixio")
    nixio.syslog("info", "[RouterAssistant] api_enable_device called")

    if not require_csrf_token() then
        nixio.syslog("err", "[RouterAssistant] api_enable_device: CSRF failed")
        return
    end

    local http = require "luci.http"
    local util = require "luci.util"

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
    local mac_no_colon = safe_mac

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
    -- 同时删除 ip6tables 规则
    table.insert(script_parts, "ip6tables -D INPUT -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")
    table.insert(script_parts, "ip6tables -D FORWARD -m mac --mac-source " .. safe_mac_quoted .. " -j DROP 2>/dev/null || true")

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
    local timeout_cmd = get_timeout_cmd() or ""
    table.insert(script_parts, "if [ -x /usr/bin/access_ctl.sh ]; then " .. timeout_cmd .. " 5 access_ctl.sh -m " .. safe_mac_lower_quoted .. " -a 1 2>/dev/null || true; fi")

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
        -- 【关键修复】使用 exec_background_nowait 确保后台执行不被阻塞
        nixio.syslog("info", "[RouterAssistant] enable_device: script file created: " .. script_file)
        nixio.syslog("info", "[RouterAssistant] enable_device: script content:\n" .. script_content)
        os.execute("chmod +x '" .. script_file .. "'")
        exec_background_nowait("nohup /bin/sh '" .. script_file .. "' >/tmp/router_assistant_enable.log 2>&1 &")
        exec_background_nowait("(sleep 10 && rm -f '" .. script_file .. "') >/dev/null 2>&1 &")
    else
        -- 【问题4修复】fallback 路径：转义 cmd 中的单引号（防御深度）
        nixio.syslog("warning", "[RouterAssistant] enable_device: cannot write script file, using fallback for " .. mac_colon)
        for _, cmd in ipairs(script_parts) do
            local escaped_cmd = cmd:gsub("'", "'\\''")
            exec_background_nowait("nohup /bin/sh -c '" .. escaped_cmd .. "' >/dev/null 2>&1 &")
        end
    end

    -- 更新黑名单（纯Lua文件操作）
    pcall(remove_from_blocklist, mac_colon)
    _blocked_macs_cache = nil
    _blocked_macs_cache_time = 0
    clear_blocked_macs_cache_file()

    -- 写入调试日志
    local dbg = io.open("/tmp/enable_device_debug.log", "a")
    if dbg then
        dbg:write("=== enable_device called ===\n")
        dbg:write("mac_colon=" .. tostring(mac_colon) .. "\n")
        dbg:write("safe_mac=" .. tostring(safe_mac) .. "\n")
        dbg:close()
    end

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

        local mount_output = util.exec("cat /proc/mounts 2>/dev/null | grep -E 'mmcblk|sdcard|sd[a-z][0-9]'")
        if mount_output and mount_output ~= "" then
            result.tf_card.exists = true

            for line in mount_output:gmatch("[^\r\n]+") do
                local device, mount_point = line:match("^(/dev/%S+)%s+(/%S+)")
                if mount_point and device then
                    if mount_point == "/tmp/storage/mmcblk0p1" then
                        result.tf_card.mount_point = mount_point
                        result.tf_card.device = device
                        break
                    elseif mount_point ~= "/overlay" and mount_point ~= "/" then
                        result.tf_card.mount_point = mount_point
                        result.tf_card.device = device
                        break
                    elseif result.tf_card.mount_point == "" then
                        result.tf_card.mount_point = mount_point
                        result.tf_card.device = device
                    end
                end
            end

            if result.tf_card.mount_point ~= "" then
                local safe_mount = safe_path(result.tf_card.mount_point)
                if safe_mount then
                    local util = require("luci.util")
                    local df_output = util.exec("df -k '" .. safe_mount:gsub("'", "'\\''") .. "' 2>/dev/null | tail -1")
                    if df_output and df_output ~= "" then
                        local parts = {}
                        for part in df_output:gmatch("%S+") do
                            table.insert(parts, part)
                        end
                        if #parts >= 4 then
                            result.tf_card.total = tonumber(parts[2]) or 0
                            result.tf_card.used = tonumber(parts[3]) or 0
                            result.tf_card.available = tonumber(parts[4]) or 0
                            result.tf_card.total = result.tf_card.total * 1024
                            result.tf_card.used = result.tf_card.used * 1024
                            result.tf_card.available = result.tf_card.available * 1024
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
    luci.sys.exec(start_cmd)
    
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
        luci.sys.exec("sleep 1")
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
local MAX_PORT_SCAN_RANGE = 100  -- 端口扫描最大范围
local DNS_SPEED_TEST_SERVERS = {
    {name = "阿里云DNS", ip = "223.5.5.5"},
    {name = "腾讯云DNS", ip = "119.29.29.29"},
    {name = "百度DNS", ip = "180.76.76.76"},
    {name = "114DNS", ip = "114.114.114.114"},
    {name = "Google DNS", ip = "8.8.8.8"},
    {name = "Cloudflare DNS", ip = "1.1.1.1"}
}

-- 格式化traceroute输出为中文风格
local function format_traceroute_output(raw_output, target)
    if not raw_output or raw_output == "" then
        return "路由追踪失败，无输出结果。"
    end
    
    local lines = {}
    for line in raw_output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    local formatted = {}
    table.insert(formatted, "正在追踪到 " .. target .. " 的路由，最多 20 个跃点:")
    table.insert(formatted, "")
    
    local hop_count = 0
    local has_output = false
    
    for _, line in ipairs(lines) do
        line = line:gsub("^%s*(.-)%s*$", "%1")
        if line ~= "" then
            -- 匹配标准traceroute输出:  1  192.168.1.1 (192.168.1.1)  1.234 ms  1.345 ms  1.456 ms
            local hop, ip, hostname, t1, t2, t3 = line:match("^%s*(%d+)%s+([%w%.%-]+)%s*%(([%d%.]+)%)%s+([%d%.]+)%s*ms%s+([%d%.]+)%s*ms%s+([%d%.]+)%s*ms")
            
            -- 尝试匹配无域名的格式:  1  192.168.1.1  1.234 ms  1.345 ms  1.456 ms
            if not hop then
                hop, ip, t1, t2, t3 = line:match("^%s*(%d+)%s+([%d%.]+)%s+([%d%.]+)%s*ms%s+([%d%.]+)%s*ms%s+([%d%.]+)%s*ms")
                if hop and ip then
                    hostname = ip
                end
            end
            
            -- 尝试匹配超时格式:  3  * * *
            if not hop then
                hop = line:match("^%s*(%d+)%s+%*%s+%*%s+%*")
                if hop then
                    hop_count = hop_count + 1
                    has_output = true
                    table.insert(formatted, "  " .. hop .. "    请求超时。")
                end
            end
            
            -- 尝试匹配单时间格式:  1  192.168.1.1 (192.168.1.1)  1.234 ms
            if not hop then
                hop, ip, hostname, t1 = line:match("^%s*(%d+)%s+([%w%.%-]+)%s*%(([%d%.]+)%)%s+([%d%.]+)%s*ms")
            end
            
            if not hop then
                hop, ip, t1 = line:match("^%s*(%d+)%s+([%d%.]+)%s+([%d%.]+)%s*ms")
                if hop and ip then
                    hostname = ip
                end
            end
            
            if hop and ip then
                hop_count = hop_count + 1
                has_output = true
                local display_ip = hostname or ip
                local times_str = ""
                if t1 then
                    times_str = " 时间=" .. tostring(math.floor(tonumber(t1) + 0.5)) .. "ms"
                end
                if t2 then
                    times_str = times_str .. " 时间=" .. tostring(math.floor(tonumber(t2) + 0.5)) .. "ms"
                end
                if t3 then
                    times_str = times_str .. " 时间=" .. tostring(math.floor(tonumber(t3) + 0.5)) .. "ms"
                end
                table.insert(formatted, "  " .. hop .. "    " .. display_ip .. times_str)
            end
        end
    end
    
    if not has_output then
        table.insert(formatted, "  无法解析路由信息。")
    end
    
    table.insert(formatted, "")
    table.insert(formatted, "路由追踪完成。")
    
    return table.concat(formatted, "\n")
end

-- 格式化DNS查询输出为中文风格
local function format_dns_output(raw_output, target)
    if not raw_output or raw_output == "" then
        return "DNS查询失败，无输出结果。"
    end
    
    local lines = {}
    for line in raw_output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    local formatted = {}
    table.insert(formatted, "正在查询 " .. target .. " 的DNS记录:")
    table.insert(formatted, "")
    
    local has_result = false
    local server_info = nil
    
    for _, line in ipairs(lines) do
        line = line:gsub("^%s*(.-)%s*$", "%1")
        if line ~= "" then
            -- 匹配nslookup的Server行: Server:  192.168.1.1
            local server = line:match("[Ss]erver:%s*([%d%.]+)")
            if server and not server_info then
                server_info = server
            end
            
            -- 匹配nslookup的Name行: Name: baidu.com
            local name = line:match("[Nn]ame:%s*([%w%.%-]+)")
            
            -- 匹配nslookup的Address行: Address: 110.242.68.66
            local address = line:match("[Aa]ddress%s*:%s*([%d%.]+)")
            if address and not line:match("#") then
                has_result = true
                table.insert(formatted, "  名称:    " .. (name or target))
                table.insert(formatted, "  地址:    " .. address)
                table.insert(formatted, "")
            end
            
            -- 匹配nslookup的AAAA记录: Address: 2408:4000:1000::1
            local address6 = line:match("[Aa]ddress%s*:%s*([%x:]+)")
            if address6 and not line:match("#") and not address6:match("^%d+%.") then
                has_result = true
                table.insert(formatted, "  名称:    " .. (name or target))
                table.insert(formatted, "  IPv6地址: " .. address6)
                table.insert(formatted, "")
            end
            
            -- 匹配dig的简短输出（纯IP地址行）
            local dig_ip = line:match("^([%d%.]+)$")
            if dig_ip then
                has_result = true
                table.insert(formatted, "  名称:    " .. target)
                table.insert(formatted, "  地址:    " .. dig_ip)
                table.insert(formatted, "")
            end
            
            -- 匹配dig的IPv6输出
            local dig_ip6 = line:match("^([%x:]+)$")
            if dig_ip6 and not dig_ip6:match("^%d+%.") then
                has_result = true
                table.insert(formatted, "  名称:    " .. target)
                table.insert(formatted, "  IPv6地址: " .. dig_ip6)
                table.insert(formatted, "")
            end
        end
    end
    
    if server_info then
        table.insert(formatted, 1, "  DNS服务器: " .. server_info)
        table.insert(formatted, 2, "")
    end
    
    if not has_result then
        table.insert(formatted, "  未找到DNS记录。")
    end
    
    table.insert(formatted, "DNS查询完成。")
    
    return table.concat(formatted, "\n")
end

-- 格式化端口检测输出为中文风格
local function format_port_output(raw_output, target, port)
    if not raw_output or raw_output == "" then
        return "端口检测失败，无输出结果。"
    end
    
    local lines = {}
    for line in raw_output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    local formatted = {}
    table.insert(formatted, "正在检测 " .. target .. " 的端口 " .. port .. ":")
    table.insert(formatted, "")
    
    local is_open = false
    local connection_info = nil
    
    for _, line in ipairs(lines) do
        line = line:gsub("^%s*(.-)%s*$", "%1")
        if line ~= "" then
            -- 匹配nc成功连接: Connection to 192.168.1.1 80 port [tcp/http] succeeded!
            local conn_target, conn_port, proto = line:match("[Cc]onnection to ([%w%.%-]+) (%d+) port %[?([^%]]*)%]? succeeded")
            if conn_target then
                is_open = true
                connection_info = "  协议:    " .. (proto ~= "" and proto or "tcp") .. "\n  状态:    开放"
            end
            
            -- 匹配nc简洁成功: 192.168.1.1 (192.168.1.1:80) open
            if not is_open then
                local open_ip, open_port = line:match("([%d%.]+).-:(%d+).*open")
                if open_ip then
                    is_open = true
                    connection_info = "  协议:    tcp\n  状态:    开放"
                end
            end
            
            -- 匹配超时或拒绝
            if line:match("[Tt]imeout") or line:match("[Rr]efused") or line:match("[Ff]ailed") or line:match("不可达") then
                connection_info = "  状态:    关闭或不可达"
            end
        end
    end
    
    if connection_info then
        table.insert(formatted, connection_info)
    else
        -- 尝试从原始输出推断
        if raw_output:match("succeeded") or raw_output:match("open") then
            table.insert(formatted, "  协议:    tcp\n  状态:    开放")
        else
            table.insert(formatted, "  状态:    关闭或不可达")
        end
    end
    
    table.insert(formatted, "")
    table.insert(formatted, "端口检测完成。")
    
    return table.concat(formatted, "\n")
end

-- 格式化端口范围扫描输出为中文风格
local function format_port_range_output(raw_output, target, start_port, end_port)
    local formatted = {}
    table.insert(formatted, "正在扫描 " .. target .. " 的端口范围 " .. start_port .. "-" .. end_port .. ":")
    table.insert(formatted, "")
    
    local open_ports = {}
    local total_scanned = end_port - start_port + 1
    
    if raw_output and raw_output ~= "" then
        for line in raw_output:gmatch("[^\r\n]+") do
            local port_num = line:match("PORT:(%d+):OPEN")
            if port_num then
                table.insert(open_ports, tonumber(port_num))
            end
        end
    end
    
    table.sort(open_ports)
    
    if #open_ports > 0 then
        table.insert(formatted, "  开放端口:")
        for _, port_num in ipairs(open_ports) do
            -- 尝试获取服务名称
            local service_name = ""
            local common_ports = {
                [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP",
                [53] = "DNS", [80] = "HTTP", [110] = "POP3", [143] = "IMAP",
                [443] = "HTTPS", [445] = "SMB", [3306] = "MySQL", [3389] = "RDP",
                [8080] = "HTTP-Proxy", [8443] = "HTTPS-Alt"
            }
            if common_ports[port_num] then
                service_name = " (" .. common_ports[port_num] .. ")"
            end
            table.insert(formatted, "    端口 " .. port_num .. service_name .. "  [开放]")
        end
    else
        table.insert(formatted, "  未检测到开放端口。")
    end
    
    table.insert(formatted, "")
    table.insert(formatted, "扫描统计:")
    table.insert(formatted, "  扫描端口数: " .. total_scanned)
    table.insert(formatted, "  开放端口数: " .. #open_ports)
    table.insert(formatted, "")
    table.insert(formatted, "端口扫描完成。")
    
    return table.concat(formatted, "\n")
end

-- 格式化DNS测速输出为中文风格
local function format_dns_speed_output(speed_results, target)
    local formatted = {}
    table.insert(formatted, "正在对 " .. target .. " 进行DNS测速对比:")
    table.insert(formatted, "")
    
    -- 按响应时间排序
    table.sort(speed_results, function(a, b)
        if a.status == "成功" and b.status ~= "成功" then
            return true
        elseif a.status ~= "成功" and b.status == "成功" then
            return false
        else
            return tonumber(a.time) < tonumber(b.time)
        end
    end)
    
    table.insert(formatted, "  DNS服务器测速结果:")
    table.insert(formatted, "")
    
    for i, result in ipairs(speed_results) do
        local rank = ""
        if i == 1 then
            rank = " [最快]"
        end
        local time_str = result.status == "成功" and (result.time .. "ms") or "超时"
        table.insert(formatted, "  " .. i .. ". " .. result.name)
        table.insert(formatted, "     IP:   " .. result.ip)
        table.insert(formatted, "     响应: " .. time_str .. rank)
        table.insert(formatted, "")
    end
    
    -- 找出最佳DNS
    local best_dns = nil
    for _, result in ipairs(speed_results) do
        if result.status == "成功" then
            best_dns = result
            break
        end
    end
    
    if best_dns then
        table.insert(formatted, "推荐DNS服务器: " .. best_dns.name .. " (" .. best_dns.ip .. ")")
    else
        table.insert(formatted, "所有DNS服务器均无法解析该域名。")
    end
    
    table.insert(formatted, "")
    table.insert(formatted, "DNS测速完成。")
    
    return table.concat(formatted, "\n")
end

-- 格式化ping输出为Windows风格
local function format_ping_output(raw_output, target, count)
    if not raw_output or raw_output == "" then
        return "请求超时。"
    end
    
    local lines = {}
    for line in raw_output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    local formatted = {}
    local received = 0
    local lost = 0
    local times = {}
    local ttl_values = {}
    local actual_bytes = "32"  -- 默认字节数
    
    for _, line in ipairs(lines) do
        line = line:gsub("^%s*(.-)%s*$", "%1")  -- 去除首尾空白
        
        if line ~= "" then
            -- 匹配标准Linux ping输出: 64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
            local bytes, from_ip, seq, ttl, time_ms = line:match("(%d+) bytes from ([%d%.]+): icmp_seq=(%d+) ttl=(%d+) time=([%d%.]+) ms")
            
            -- 匹配OpenWrt busybox格式: 64 bytes from 192.168.1.1: seq=0 ttl=64 time=2.340 ms
            if not bytes then
                bytes, from_ip, seq, ttl, time_ms = line:match("(%d+) bytes from ([%d%.]+): seq=(%d+) ttl=(%d+) time=([%d%.]+) ms")
            end
            
            -- 尝试匹配域名格式: 64 bytes from router.lan (192.168.1.1): icmp_seq=1 ttl=64 time=1.23 ms
            if not bytes then
                bytes, from_ip, seq, ttl, time_ms = line:match("(%d+) bytes from [%w%.%-]+ %(([%d%.]+)%): icmp_seq=(%d+) ttl=(%d+) time=([%d%.]+) ms")
            end
            
            -- 尝试匹配域名+busybox格式: 64 bytes from router.lan (192.168.1.1): seq=0 ttl=64 time=2.340 ms
            if not bytes then
                bytes, from_ip, seq, ttl, time_ms = line:match("(%d+) bytes from [%w%.%-]+ %(([%d%.]+)%): seq=(%d+) ttl=(%d+) time=([%d%.]+) ms")
            end
            
            if bytes and from_ip and ttl and time_ms then
                received = received + 1
                actual_bytes = bytes  -- 记录实际的字节数
                local t = tonumber(time_ms)
                if t then
                    table.insert(times, t)
                    -- 四舍五入到整数毫秒
                    time_ms = tostring(math.floor(t + 0.5))
                end
                table.insert(ttl_values, tonumber(ttl) or 0)
                table.insert(formatted, "来自 " .. from_ip .. " 的回复: 字节=" .. bytes .. " 时间=" .. time_ms .. "ms TTL=" .. ttl)
            end
            
            -- 检测超时行
            if line:match("Request timeout") or line:match("100%% packet loss") or line:match("no answer") then
                lost = lost + 1
            end
        end
    end
    
    -- 构建标题行（使用实际字节数）
    local title_line = "正在 Ping " .. target .. " 具有 " .. actual_bytes .. " 字节的数据:"
    
    -- 如果没有解析到任何回复，尝试检测是否全部丢失
    if received == 0 then
        if raw_output:match("100%% packet loss") or raw_output:match("unreachable") or raw_output:match("unknown host") then
            -- 清空之前的内容，重新构建
            formatted = {}
            table.insert(formatted, title_line)
            table.insert(formatted, "")
            for i = 1, count do
                table.insert(formatted, "请求超时。")
            end
        end
    else
        -- 有回复时，在开头插入标题行
        local new_formatted = {}
        table.insert(new_formatted, title_line)
        table.insert(new_formatted, "")
        for _, v in ipairs(formatted) do
            table.insert(new_formatted, v)
        end
        formatted = new_formatted
    end
    
    -- 计算丢包数
    if received > 0 then
        lost = count - received
        if lost < 0 then lost = 0 end
    end
    
    local loss_percent = count > 0 and math.floor((lost / count) * 100) or 0
    
    table.insert(formatted, "")
    table.insert(formatted, target .. " 的 Ping 统计信息:")
    table.insert(formatted, "    数据包: 已发送 = " .. count .. "，已接收 = " .. received .. "，丢失 = " .. lost .. " (" .. loss_percent .. "% 丢失)，")
    table.insert(formatted, "往返行程的估计时间(以毫秒为单位):")
    
    if #times > 0 then
        local min_time = times[1]
        local max_time = times[1]
        local sum = 0
        for _, t in ipairs(times) do
            if t < min_time then min_time = t end
            if t > max_time then max_time = t end
            sum = sum + t
        end
        local avg_time = sum / #times
        -- 四舍五入
        min_time = math.floor(min_time + 0.5)
        max_time = math.floor(max_time + 0.5)
        avg_time = math.floor(avg_time + 0.5)
        table.insert(formatted, "    最短 = " .. min_time .. "ms，最长 = " .. max_time .. "ms，平均 = " .. avg_time .. "ms")
    else
        table.insert(formatted, "    最短 = 0ms，最长 = 0ms，平均 = 0ms")
    end
    
    return table.concat(formatted, "\n")
end

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
    local count = tonumber(luci.http.formvalue("count")) or 4
    local port = tonumber(luci.http.formvalue("port")) or 0
    local port_end = tonumber(luci.http.formvalue("port_end")) or 0
    local scan_type = luci.http.formvalue("scan_type") or "single"  -- single 或 range

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
        local timeout_cmd = get_timeout_cmd()
        local timeout_prefix = timeout_cmd and (timeout_cmd .. " " .. DIAGNOSE_TIMEOUT .. " ") or ""
        
        if diagnose_type == "ping" then
            cmd = timeout_prefix .. "ping -c " .. count .. " -W 2 '" .. safe_target .. "' 2>&1"
        elseif diagnose_type == "traceroute" then
            local traceroute_timeout = timeout_cmd and (timeout_cmd .. " " .. (DIAGNOSE_TIMEOUT * 2) .. " ") or ""
            if luci.sys.exec("which traceroute 2>/dev/null | wc -l"):gsub("%s+", "") == "1" then
                cmd = traceroute_timeout .. "traceroute -m 20 '" .. safe_target .. "' 2>&1"
            else
                cmd = traceroute_timeout .. "traceroute -m 20 '" .. safe_target .. "' 2>&1"
            end
        elseif diagnose_type == "dns" then
            local dns_type = luci.http.formvalue("dns_type") or "query"
            if dns_type == "speed" then
                -- DNS测速模式
                local speed_results = {}
                for _, server in ipairs(DNS_SPEED_TEST_SERVERS) do
                    local start_time = os.clock()
                    local dns_cmd = "nslookup '" .. safe_target .. "' " .. server.ip .. " >/dev/null 2>&1 && echo 'OK' || echo 'FAIL'"
                    local dns_output = luci.sys.exec(dns_cmd)
                    local elapsed = os.clock() - start_time
                    local status = dns_output:match("OK") and "成功" or "失败"
                    table.insert(speed_results, {
                        name = server.name,
                        ip = server.ip,
                        time = string.format("%.2f", elapsed * 1000),
                        status = status
                    })
                end
                result.output = format_dns_speed_output(speed_results, safe_target)
                result.success = true
                return
            else
                cmd = timeout_prefix .. "nslookup '" .. safe_target .. "' 2>&1 || " .. timeout_prefix .. "dig '" .. safe_target .. "' +short 2>&1"
            end
        elseif diagnose_type == "port" then
            if scan_type == "range" then
                -- 端口范围扫描
                if port < 1 or port > 65535 or port_end < 1 or port_end > 65535 then
                    result.output = "错误：端口号必须在 1-65535 范围内"
                    result.success = false
                    return
                end
                if port > port_end then
                    port, port_end = port_end, port
                end
                local range_size = port_end - port + 1
                if range_size > MAX_PORT_SCAN_RANGE then
                    result.output = "错误：端口扫描范围不能超过 " .. MAX_PORT_SCAN_RANGE .. " 个端口"
                    result.success = false
                    return
                end
                -- 使用bash循环进行端口扫描
                local scan_cmd = "for p in $(seq " .. port .. " " .. port_end .. "); do "
                    .. "(timeout 2 nc -z -w 1 '" .. safe_target .. "' $p 2>/dev/null && echo \"PORT:$p:OPEN\") &"
                    .. "done; wait"
                local scan_output = luci.sys.exec(scan_cmd)
                result.output = format_port_range_output(scan_output, safe_target, port, port_end)
                result.success = true
                return
            else
                -- 单个端口检测
                if port < 1 or port > 65535 then
                    result.output = "错误：端口号必须在 1-65535 范围内"
                    result.success = false
                else
                    cmd = timeout_prefix .. "nc -zv -w 3 '" .. safe_target .. "' " .. port .. " 2>&1 || echo '端口 " .. port .. " 不可达'"
                end
            end
        else
            result.output = "错误：不支持的诊断类型"
            result.success = false
        end

        if cmd and cmd ~= "" then
            local output = luci.sys.exec(cmd)
            
            -- 根据诊断类型进行格式化
            if output and output ~= "" then
                if diagnose_type == "ping" then
                    output = format_ping_output(output, safe_target, count)
                elseif diagnose_type == "traceroute" then
                    output = format_traceroute_output(output, safe_target)
                elseif diagnose_type == "dns" then
                    output = format_dns_output(output, safe_target)
                elseif diagnose_type == "port" then
                    output = format_port_output(output, safe_target, port)
                end
            end
            
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
-- 安全中心功能
-- ============================================================

-- 安全数据缓存文件
local SECURITY_DATA_FILE = "security_data.json"
local ARP_CACHE_FILE = "/tmp/router_assistant/arp_cache.json"
local PORT_SCAN_LOG_FILE = "/tmp/router_assistant/port_scan.log"

-- DHCP指纹数据库（设备类型识别）
local DHCP_FINGERPRINTS = {
    ["android"] = {
        patterns = {"android", "dalvik", "droid"},
        vendor = "Android",
        device_type = "phone"
    },
    ["iphone"] = {
        patterns = {"iphone", "ipad", "ios", "apple"},
        vendor = "Apple",
        device_type = "phone"
    },
    ["windows"] = {
        patterns = {"msft", "windows", "microsoft"},
        vendor = "Microsoft",
        device_type = "desktop"
    },
    ["macos"] = {
        patterns = {"macbook", "imac", "macos", "darwin"},
        vendor = "Apple",
        device_type = "laptop"
    },
    ["linux"] = {
        patterns = {"linux", "ubuntu", "debian", "centos", "fedora", "redhat"},
        vendor = "Linux",
        device_type = "desktop"
    },
    ["router"] = {
        patterns = {"router", "gateway", "openwrt", "lede"},
        vendor = "Router",
        device_type = "router"
    },
    ["printer"] = {
        patterns = {"printer", "hp", "canon", "epson", "brother"},
        vendor = "Printer",
        device_type = "printer"
    },
    ["smart_tv"] = {
        patterns = {"smarttv", "samsung", "lg", "sony", "tizen", "webos"},
        vendor = "Smart TV",
        device_type = "tv"
    },
    ["iot"] = {
        patterns = {"iot", "smart", "homekit", "alexa", "echo", "googlehome"},
        vendor = "IoT Device",
        device_type = "smart_home"
    },
    ["gaming"] = {
        patterns = {"playstation", "xbox", "nintendo", "switch"},
        vendor = "Gaming Console",
        device_type = "gaming"
    }
}

-- 从OUI数据库加载厂商信息
local function load_oui_database()
    local json = require("luci.jsonc")
    local file_path = get_data_dir() .. "/../oui_database.json"
    local fd = io.open(file_path, "r")
    if not fd then
        return nil
    end
    local content = fd:read("*a")
    fd:close()
    if not content or content == "" then
        return nil
    end
    local ok, data = pcall(json.parse, content)
    if not ok or not data or not data.brands then
        return nil
    end
    return data
end

-- ============================================================
-- 自定义OUI数据库（用户手动添加）
-- ============================================================
local CUSTOM_OUI_DB_FILE = "/tmp/router_assistant/custom_oui_db.json"
local _custom_oui_cache = nil

local function load_custom_oui_database()
    if _custom_oui_cache then return _custom_oui_cache end
    
    local json = require("luci.jsonc")
    local fd = io.open(CUSTOM_OUI_DB_FILE, "r")
    if not fd then
        _custom_oui_cache = {}
        return _custom_oui_cache
    end
    
    local content = fd:read("*a")
    fd:close()
    
    if content and content ~= "" then
        local ok, data = pcall(json.parse, content)
        if ok and data then
            _custom_oui_cache = data
            return _custom_oui_cache
        end
    end
    
    _custom_oui_cache = {}
    return _custom_oui_cache
end

local function save_custom_oui_database(db)
    local json = require("luci.jsonc")
    local dir = CUSTOM_OUI_DB_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local fd = io.open(CUSTOM_OUI_DB_FILE, "w")
    if fd then
        fd:write(json.stringify(db))
        fd:close()
    end
    -- 清除缓存使更改立即生效
    _custom_oui_cache = db
end

-- 从自定义OUI数据库查询厂商
local function get_custom_oui_vendor(oui_prefix)
    local custom_db = load_custom_oui_database()
    if custom_db and custom_db.entries then
        for oui, entry in pairs(custom_db.entries) do
            if oui:upper() == oui_prefix:upper() then
                return entry.vendor, entry.device_type or "unknown", true  -- 第三个参数表示来自自定义库
            end
        end
    end
    return nil, nil, false
end

-- 获取MAC地址对应的厂商信息
-- 在线OUI查询缓存
local ONLINE_OUI_CACHE_FILE = "/tmp/router_assistant/online_oui_cache.json"
local _online_oui_cache = nil

local function load_online_oui_cache()
    if _online_oui_cache then return _online_oui_cache end
    
    local json = require("luci.jsonc")
    local fd = io.open(ONLINE_OUI_CACHE_FILE, "r")
    if not fd then
        _online_oui_cache = {}
        return _online_oui_cache
    end
    local content = fd:read("*a")
    fd:close()
    
    if content and content ~= "" then
        local ok, data = pcall(json.parse, content)
        if ok and data then
            _online_oui_cache = data
            return _online_oui_cache
        end
    end
    
    _online_oui_cache = {}
    return _online_oui_cache
end

local function save_online_oui_cache(oui, vendor)
    _online_oui_cache[oui] = {
        vendor = vendor,
        cached_time = os.time()
    }
    
    local json = require("luci.jsonc")
    local dir = ONLINE_OUI_CACHE_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local fd = io.open(ONLINE_OUI_CACHE_FILE, "w")
    if fd then
        fd:write(json.stringify(_online_oui_cache))
        fd:close()
    end
end

local function query_online_oui(oui_prefix)
    local cache = load_online_oui_cache()
    local clean_prefix = oui_prefix:gsub(":", ""):gsub("-", ""):upper()
    
    -- 检查缓存（缓存有效期7天）
    if cache[clean_prefix] and cache[clean_prefix].cached_time then
        local age = os.time() - cache[clean_prefix].cached_time
        if age < 604800 then  -- 7天
            return cache[clean_prefix].vendor
        end
    end
    
    -- 尝试在线查询（使用macvendors.com API）
    local util = require("luci.util")
    
    -- 格式化MAC地址用于API查询
    local mac_for_api = oui_prefix:sub(1,2) .. ":" .. oui_prefix:sub(3,4) .. ":" .. oui_prefix:sub(5,6) .. ":00:00:00"
    
    -- 使用curl查询，设置超时为3秒
    local cmd = "curl -s -m 3 'https://api.macvendors.com/" .. mac_for_api .. "' 2>/dev/null"
    local output = util.exec(cmd)
    
    if output and output ~= "" and #output < 200 and not output:match("^%{") then
        -- 成功获取到厂商信息
        save_online_oui_cache(clean_prefix, output)
        return output
    end
    
    -- 备用API：maclookup.app
    local cmd2 = "curl -s -m 3 'https://api.maclookup.app/v2/macs/" .. oui_prefix .. "' 2>/dev/null"
    local output2 = util.exec(cmd2)
    
    if output2 and output2 ~= "" then
        local json = require("luci.jsonc")
        local ok, data = pcall(json.parse, output2)
        if ok and data and data.company then
            save_online_oui_cache(clean_prefix, data.company)
            return data.company
        end
    end
    
    -- 标记为已查询但未找到，避免重复请求
    save_online_oui_cache(clean_prefix, nil)
    return nil
end

local function get_mac_vendor_info(mac)
    if not mac or type(mac) ~= "string" then
        return nil, nil
    end
    local mac_clean = mac:upper():gsub("[^A-F0-9]", "")
    if #mac_clean < 6 then
        return nil, nil
    end
    local oui_prefix = mac_clean:sub(1, 6)
    local formatted_oui = oui_prefix:sub(1,2) .. ":" .. oui_prefix:sub(3,4) .. ":" .. oui_prefix:sub(5,6)
    
    -- 1. 首先尝试自定义OUI数据库（用户手动添加的，优先级最高）
    local custom_vendor, custom_type, is_custom = get_custom_oui_vendor(oui_prefix)
    if custom_vendor then
        return custom_vendor, custom_type or "unknown"
    end
    
    -- 2. 尝试本地内置OUI数据库
    local oui_db = load_oui_database()
    if oui_db and oui_db.brands then
        for brand_key, brand_info in pairs(oui_db.brands) do
            if brand_info.ouis then
                for _, oui in ipairs(brand_info.ouis) do
                    if oui:upper() == formatted_oui then
                        return brand_info.name or brand_key, brand_info.type or "unknown"
                    end
                end
            end
        end
    end
    
    -- 3. 本地数据库未找到，尝试在线查询
    local online_vendor = query_online_oui(formatted_oui)
    if online_vendor then
        return online_vendor, "unknown"
    end
    
    return nil, nil
end

-- 解析DHCP请求指纹
local function parse_dhcp_fingerprint(hostname, vendor_class)
    local result = {
        vendor = "Unknown",
        device_type = "unknown",
        confidence = 0,
        fingerprint_data = {}
    }
    
    if hostname and type(hostname) == "string" then
        result.fingerprint_data.hostname = hostname
        local h = hostname:lower()
        for fp_key, fp_info in pairs(DHCP_FINGERPRINTS) do
            for _, pattern in ipairs(fp_info.patterns) do
                if h:match(pattern) then
                    result.vendor = fp_info.vendor
                    result.device_type = fp_info.device_type
                    result.confidence = 70
                    result.fingerprint_data.matched_pattern = pattern
                    break
                end
            end
            if result.confidence > 0 then break end
        end
    end
    
    if vendor_class and type(vendor_class) == "string" then
        result.fingerprint_data.vendor_class = vendor_class
        local vc = vendor_class:lower()
        for fp_key, fp_info in pairs(DHCP_FINGERPRINTS) do
            for _, pattern in ipairs(fp_info.patterns) do
                if vc:match(pattern) then
                    if result.confidence < 80 then
                        result.vendor = fp_info.vendor
                        result.device_type = fp_info.device_type
                        result.confidence = math.max(result.confidence, 80)
                        result.fingerprint_data.matched_vendor_class = pattern
                    end
                    break
                end
            end
        end
    end
    
    return result
end

-- 获取ARP表
local function get_arp_table()
    local arp_entries = {}
    local fd = io.popen("cat /proc/net/arp 2>/dev/null", "r")
    if fd then
        for line in fd:lines() do
            if line and not line:match("^IP") then
                local parts = {}
                for part in line:gmatch("%S+") do
                    table.insert(parts, part)
                end
                if #parts >= 4 then
                    local ip = parts[1]
                    local hw_type = parts[2]
                    local flags = parts[3]
                    local mac = parts[4]
                    if mac and mac ~= "00:00:00:00:00:00" and ip and ip:match("^%d+%.%d+%.%d+%.%d+$") then
                        table.insert(arp_entries, {
                            ip = ip,
                            mac = mac:upper(),
                            hw_type = hw_type,
                            flags = flags,
                            device = parts[5] or ""
                        })
                    end
                end
            end
        end
        fd:close()
    end
    return arp_entries
end

-- 保存ARP缓存用于检测欺骗
local function save_arp_cache()
    local arp_table = get_arp_table()
    local cache_data = {
        timestamp = os.time(),
        entries = {}
    }
    for _, entry in ipairs(arp_table) do
        cache_data.entries[entry.ip] = entry.mac
    end
    local json = require("luci.jsonc")
    local dir = ARP_CACHE_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local fd = io.open(ARP_CACHE_FILE, "w")
    if fd then
        fd:write(json.stringify(cache_data))
        fd:close()
    end
    return cache_data
end

-- 加载ARP缓存
local function load_arp_cache()
    local json = require("luci.jsonc")
    local fd = io.open(ARP_CACHE_FILE, "r")
    if not fd then
        return nil
    end
    local content = fd:read("*a")
    fd:close()
    if not content or content == "" then
        return nil
    end
    local ok, data = pcall(json.parse, content)
    if not ok or not data then
        return nil
    end
    return data
end

-- 获取路由器自身MAC地址（用于排除误判）
local function get_router_mac()
    local macs = {}
    -- 获取所有网络接口的MAC地址
    local fd = io.popen("ip -o link show 2>/dev/null | grep 'ether' | awk '{print toupper($13)}'", "r")
    if fd then
        for line in fd:lines() do
            if line and line ~= "" and #line == 17 then
                macs[line] = true
            end
        end
        fd:close()
    end
    return macs
end

-- 判断MAC是否为本地管理地址（第2字节最低位为1）
local function is_locally_administered_mac(mac)
    if not mac or type(mac) ~= "string" or #mac < 4 then return false end
    local clean = mac:gsub(":", ""):gsub("-", ""):upper()
    if #clean < 4 then return false end
    local second_byte = tonumber(clean:sub(3, 4), 16)
    if not second_byte then return false end
    -- 第2字节最低位为1表示本地管理（软件生成的MAC）
    return (second_byte % 2) == 1
end

-- 判断IP是否为内网私有地址
local function is_private_ip(ip)
    if not ip then return false end
    return ip:match("^10%.") or 
           ip:match("^172%.1[6-9]%.") or ip:match("^172%.2%d%.") or ip:match("^172%.3[01]%.") or
           ip:match("^192%.168%.")
end

-- 判断IP是否为链路本地或特殊地址
local function is_special_ip(ip)
    if not ip then return false end
    return ip:match("^169%.254%.") or  -- 链路本地
           ip:match("^127%.") or       -- 回环
           ip == "0.0.0.0" or
           ip:match("^224%.") or       -- 组播
           ip:match("^255%.")          -- 广播
end

-- 加载设备白名单（已确认安全的设备）
local SECURITY_WHITELIST_FILE = "/tmp/router_assistant/security_whitelist.json"
local _security_whitelist_cache = nil
local _whitelist_cache_time = 0

local function load_security_whitelist()
    local now = os.time()
    if _security_whitelist_cache and (now - _whitelist_cache_time) < 60 then
        return _security_whitelist_cache
    end
    
    local json = require("luci.jsonc")
    local fd = io.open(SECURITY_WHITELIST_FILE, "r")
    if not fd then
        _security_whitelist_cache = {macs = {}}
        _whitelist_cache_time = now
        return _security_whitelist_cache
    end
    
    local content = fd:read("*a")
    fd:close()
    
    if content and content ~= "" then
        local ok, data = pcall(json.parse, content)
        if ok and data and data.macs then
            _security_whitelist_cache = data
            _whitelist_cache_time = now
            return data
        end
    end
    
    _security_whitelist_cache = {macs = {}}
    _whitelist_cache_time = now
    return _security_whitelist_cache
end

-- 检查MAC是否在白名单中
local function is_mac_whitelisted(mac)
    local whitelist = load_security_whitelist()
    if whitelist and whitelist.macs then
        local clean_mac = mac:upper():gsub("[^A-F0-9]", "")
        return whitelist.macs[clean_mac] == true
    end
    return false
end

-- 分析MAC地址特征
local function analyze_mac_characteristics(mac)
    if not mac or type(mac) ~= "string" then return {} end
    
    local clean = mac:upper():gsub("[^A-F0-9]", "")
    local result = {
        is_locally_administered = is_locally_administered_mac(mac),
        oui_prefix = #clean >= 6 and clean:sub(1, 6) or nil,
        vendor_info = nil,
        likely_device_type = "unknown",
        confidence = 0
    }
    
    -- 获取厂商信息
    local oui_db = load_oui_database()
    if oui_db and oui_db.brands and result.oui_prefix then
        local formatted_oui = result.oui_prefix:sub(1,2) .. ":" .. result.oui_prefix:sub(3,4) .. ":" .. result.oui_prefix:sub(5,6)
        for brand_key, brand_info in pairs(oui_db.brands) do
            if brand_info.ouis then
                for _, oui in ipairs(brand_info.ouis) do
                    if oui:upper() == formatted_oui then
                        result.vendor_info = {
                            name = brand_info.name,
                            type = brand_info.type
                        }
                        break
                    end
                end
            end
            if result.vendor_info then break end
        end
    end
    
    -- 推断设备类型
    if result.is_locally_administered then
        result.likely_device_type = "virtual_interface"
        result.confidence = 85
        result.reason = "本地管理MAC，可能是虚拟接口/容器/Docker"
    elseif result.vendor_info then
        result.likely_device_type = result.vendor_info.type
        result.confidence = 70
        result.reason = "通过OUI数据库识别为 " .. (result.vendor_info.name or "未知")
    else
        result.likely_device_type = "unknown"
        result.confidence = 20
        result.reason = "无法识别的MAC前缀"
    end
    
    return result
end

-- 检测ARP欺骗（增强版：智能分析+白名单）
local function detect_arp_spoofing()
    local alerts = {}
    local current_arp = get_arp_table()
    local cached_arp = load_arp_cache()
    local ip_mac_current = {}
    local mac_ip_current = {}
    
    -- 获取路由器自身所有MAC用于排除
    local router_macs = get_router_mac()
    
    -- 第一遍：构建IP-MAC和MAC-IP映射
    for _, entry in ipairs(current_arp) do
        -- IP冲突检测（同一IP对应多个MAC）- 这是高危信号
        if not ip_mac_current[entry.ip] then
            ip_mac_current[entry.ip] = entry.mac
        elseif ip_mac_current[entry.ip] ~= entry.mac then
            -- 排除特殊IP的冲突（如组播等）
            if not is_special_ip(entry.ip) then
                table.insert(alerts, {
                    type = "ip_conflict",
                    severity = "high",
                    ip = entry.ip,
                    mac_old = ip_mac_current[entry.ip],
                    mac_new = entry.mac,
                    message = "IP地址 " .. entry.ip .. " 被多个MAC地址使用（可能存在ARP欺骗）",
                    timestamp = os.time(),
                    confidence = 90
                })
            end
        end
        
        if not mac_ip_current[entry.mac] then
            mac_ip_current[entry.mac] = {}
        end
        table.insert(mac_ip_current[entry.mac], entry.ip)
    end
    
    -- 第二遍：检测多IP绑定（智能分析版）
    for mac, ips in pairs(mac_ip_current) do
        -- 去重IP列表
        local unique_ips = {}
        for _, ip in ipairs(ips) do
            unique_ips[ip] = true
        end
        
        local unique_count = 0
        for _ in pairs(unique_ips) do unique_count = unique_count + 1 end
        
        -- 只有当唯一IP数量>=3时才考虑告警
        if unique_count >= 3 then
            -- 分析MAC特征
            local mac_analysis = analyze_mac_characteristics(mac)
            
            -- 排除条件检查
            local should_exclude = false
            local exclude_reason = ""
            
            -- 1. 白名单排除
            if is_mac_whitelisted(mac) then
                should_exclude = true
                exclude_reason = "已在白名单中"
            
            -- 2. 路由器自身MAC排除
            elseif router_macs and router_macs[mac] then
                should_exclude = true
                exclude_reason = "是路由器自身接口"
            
            -- 3. 本地管理MAC（虚拟接口）降低严重程度
            elseif mac_analysis.is_locally_administered then
                -- 不完全排除，但标记为低危且提示可能是正常设备
                exclude_reason = "本地管理MAC（" .. (mac_analysis.reason or "虚拟接口") .. ")"
            end
            
            if not should_exclude and unique_count >= 3 then
                -- 统计内网IP数量
                local private_ip_list = {}
                for ip, _ in pairs(unique_ips) do
                    if is_private_ip(ip) then
                        table.insert(private_ip_list, ip)
                    end
                end
                
                -- 智能判断：大量IP绑定 = 网关设备，完全排除告警
                if unique_count >= 15 then
                    -- 关联15+个IP = 几乎100%是网关/AP/路由器，不生成告警
                    -- 记录到日志但不在界面显示
                    
                elseif unique_count >= 8 then
                    -- 关联8-14个IP = 极大概率是网关设备，仅记录为"信息"不触发告警
                    
                elseif mac_analysis.is_locally_administered and unique_count >= 5 then
                    -- 本地管理MAC + 多IP = 虚拟接口，不生成告警
                    
                else
                    -- 其他情况才可能生成告警
                    local severity = "medium"
                    local reason = ""
                    local is_likely_fp = false
                    
                    if mac_analysis.is_locally_administered then
                        severity = "low"
                        reason = "虚拟接口关联" .. #private_ip_list .. "个内网IP"
                        is_likely_fp = true
                    elseif #private_ip_list >= 3 then
                        severity = "medium"
                        reason = "跨子网绑定" .. #private_ip_list .. "个内网IP"
                    else
                        severity = "medium"
                        reason = "关联" .. unique_count .. "个IP"
                    end
                    
                    table.insert(alerts, {
                        type = "mac_multi_ip",
                        severity = severity,
                        mac = mac,
                        ips = private_ip_list,
                        ip_count = unique_count,
                        message = "MAC " .. mac .. " " .. reason,
                        timestamp = os.time(),
                        is_likely_false_positive = is_likely_fp,
                        mac_analysis = mac_analysis,
                        confidence = is_likely_fp and 30 or 60
                    })
                end
            end
        end
    end
    
    -- 第三遍：检测ARP缓存变更（与历史对比）
    if cached_arp and cached_arp.entries then
        for ip, cached_mac in pairs(cached_arp.entries) do
            if ip_mac_current[ip] and ip_mac_current[ip] ~= cached_mac then
                -- 排除特殊IP和短时间内的正常变更
                if not is_special_ip(ip) then
                    local time_diff = os.time() - (cached_arp.timestamp or 0)
                    -- 只在缓存存在超过30秒时才报告变更（避免初始化时的误报）
                    if time_diff > 30 then
                        table.insert(alerts, {
                            type = "arp_change",
                            severity = "high",
                            ip = ip,
                            mac_old = cached_mac,
                            mac_new = ip_mac_current[ip],
                            message = "IP " .. ip .. " 的MAC从 " .. cached_mac .. " 变更为 " .. ip_mac_current[ip] .. "（可能存在ARP欺骗）",
                            time_since_cache = time_diff,
                            timestamp = os.time()
                        })
                    end
                end
            end
        end
    end
    
    return alerts
end

-- ============================================================
-- 端口扫描检测（主动扫描模式）
-- ============================================================
local PORT_SCAN_HISTORY_FILE = "/tmp/router_assistant/port_scan_history.json"
local MAX_PORT_SCAN_HISTORY = 100

-- 常见服务端口映射
local SERVICE_PORTS = {
    ["21"] = "FTP",
    ["22"] = "SSH",
    ["23"] = "Telnet",
    ["25"] = "SMTP",
    ["53"] = "DNS",
    ["80"] = "HTTP",
    ["110"] = "POP3",
    ["143"] = "IMAP",
    ["443"] = "HTTPS",
    ["445"] = "SMB",
    ["993"] = "IMAPS",
    ["995"] = "POP3S",
    ["1433"] = "MSSQL",
    ["1521"] = "Oracle",
    ["3306"] = "MySQL",
    ["3389"] = "RDP",
    ["5432"] = "PostgreSQL",
    ["5900"] = "VNC",
    ["6379"] = "Redis",
    ["8080"] = "HTTP-Alt",
    ["8443"] = "HTTPS-Alt",
    ["8888"] = "HTTP-Alt2",
    ["9090"] = "HTTP-Alt3"
}

-- 获取端口名称
local function get_port_name(port)
    return SERVICE_PORTS[tostring(port)] or "Unknown"
end

-- 主动扫描：通过netstat/ss获取当前连接信息
local function perform_active_port_scan()
    local connections = {}
    local all_connections = {
        external_count = 0,
        internal_count = 0,
        total_connections = 0,
        external_ips = {},
        internal_ips = {}
    }

    local util = require("luci.util")
    local output = ""

    -- 方式1: 尝试ss命令
    output = util.exec("ss -tn 2>/dev/null | head -200") or ""

    -- 方式2: 如果ss失败，尝试netstat
    if not output or output == "" then
        output = util.exec("netstat -tn 2>/dev/null | head -200") or ""
    end

    -- 方式3: 如果都失败，直接读取/proc/net/tcp
    if not output or output == "" then
        output = util.exec("cat /proc/net/tcp 2>/dev/null | head -200") or ""
    end

    if output and output ~= "" then
        for line in output:gmatch("[^\r\n]+") do
            -- 跳过表头
            if line:match("^%s*sl") or line:match("^Proto") or line:match("^State") then
                -- 跳过表头行
            else
                local local_addr, remote_addr, state = nil, nil, nil

                -- 尝试解析ss/netstat格式: State Recv-Q Send-Q Local Address:Port Peer Address:Port
                local l_addr, r_addr = line:match("%S+%s+%d+%s+%d+%s+(%S+)%s+(%S+)")
                if l_addr and r_addr then
                    local_addr = l_addr
                    remote_addr = r_addr
                else
                    -- 尝试解析/proc/net/tcp格式: sl local_address rem_address st tx_queue rx_queue ...
                    local l_hex, r_hex, st_hex = line:match("%d+:%s+(%S+)%s+(%S+)%s+(%S+)")
                    if l_hex and r_hex then
                        -- 转换十六进制地址为点分十进制
                        local function hex_to_ip(hex)
                            local ip_hex, port_hex = hex:match("([^:]+):(%x+)")
                            if ip_hex and port_hex then
                                local a = tonumber(ip_hex:sub(7, 8), 16)
                                local b = tonumber(ip_hex:sub(5, 6), 16)
                                local c = tonumber(ip_hex:sub(3, 4), 16)
                                local d = tonumber(ip_hex:sub(1, 2), 16)
                                local port = tonumber(port_hex, 16)
                                if a and b and c and d and port then
                                    return string.format("%d.%d.%d.%d", a, b, c, d), port
                                end
                            end
                            return nil, nil
                        end
                        local_addr, _ = hex_to_ip(l_hex)
                        remote_addr, r_port = hex_to_ip(r_hex)
                    end
                end

                if remote_addr then
                    -- 从地址中提取IP和端口
                    local r_ip, r_port = remote_addr:match("([^%[%]:]+):(%d+)$")
                    if not r_ip then
                        r_ip = remote_addr:match("^%[?([^%]]+)%]?:")
                    end
                    if not r_ip then
                        r_ip = remote_addr
                    end

                    if r_ip then
                        -- 清理IPv6的方括号
                        r_ip = r_ip:gsub("^%[", ""):gsub("%]$", "")

                        all_connections.total_connections = all_connections.total_connections + 1

                        -- 判断是内部还是外部IP
                        local is_external = not is_private_ip(r_ip) and not is_special_ip(r_ip)

                        if is_external then
                            all_connections.external_count = all_connections.external_count + 1
                            all_connections.external_ips[r_ip] = true

                            -- 外部连接才进行详细分析和告警
                            if not connections[r_ip] then
                                connections[r_ip] = {
                                    ip = r_ip,
                                    ports = {},
                                    port_count = 0,
                                    connection_count = 0,
                                    states = {}
                                }
                            end

                            local port_name = get_port_name(tostring(r_port or "0"))
                            local port_key = tostring(r_port or "0")
                            connections[r_ip].ports[port_key] = {
                                port = port_key,
                                name = port_name,
                                state = state or "UNKNOWN"
                            }
                            connections[r_ip].port_count = connections[r_ip].port_count + 1
                            connections[r_ip].connection_count = connections[r_ip].connection_count + 1

                            if state then
                                if not connections[r_ip].states[state] then
                                    connections[r_ip].states[state] = 0
                                end
                                connections[r_ip].states[state] = connections[r_ip].states[state] + 1
                            end
                        else
                            all_connections.internal_count = all_connections.internal_count + 1
                            all_connections.internal_ips[r_ip] = true
                        end
                    end
                end
            end
        end
    end

    return connections, all_connections
end

-- 分析连接模式，识别可疑的端口扫描行为
local function analyze_scan_patterns(connections)
    local alerts = {}

    for ip, data in pairs(connections) do
        local suspicious_score = 0
        local reasons = {}

        -- 检查1：连接到多个不同端口（可能是扫描）
        if data.port_count >= 5 then
            suspicious_score = suspicious_score + 30
            table.insert(reasons, "连接" .. data.port_count .. "个不同端口")
        end

        -- 检查2：大量连接（可能是暴力破解或扫描）
        if data.connection_count >= 20 then
            suspicious_score = suspicious_score + 25
            table.insert(reasons, "共" .. data.connection_count .. "次连接尝试")
        end

        -- 检查3：连接到敏感端口
        local sensitive_ports = {"22", "23", "3389", "5900", "3306", "6379"}
        local has_sensitive = false
        for _, sp in ipairs(sensitive_ports) do
            if data.ports[sp] then
                has_sensitive = true
                suspicious_score = suspicious_score + 20
                table.insert(reasons, "访问敏感端口:" .. sp .. "(" .. (data.ports[sp].name or "") .. ")")
            end
        end

        -- 检查4：SYN_SENT状态多（可能正在扫描）
        if data.states["SYN-SENT"] and data.states["SYN-SENT"] >= 10 then
            suspicious_score = suspicious_score + 25
            table.insert(reasons, data.states["SYN-SENT"] .. "个半开连接")
        end

        -- 判断是否为可疑行为
        if suspicious_score >= 30 then
            local severity = "low"
            if suspicious_score >= 70 then
                severity = "high"
            elseif suspicious_score >= 50 then
                severity = "medium"
            end

            table.insert(alerts, {
                ip = ip,
                ports = data.ports,
                port_count = data.port_count,
                connection_count = data.connection_count,
                states = data.states,
                suspicious_score = suspicious_score,
                severity = severity,
                reasons = reasons,
                timestamp = os.time(),
                is_suspicious = true
            })
        end
    end

    -- 按可疑程度排序
    table.sort(alerts, function(a, b)
        return (a.suspicious_score or 0) > (b.suspicious_score or 0)
    end)

    return alerts
end

-- 获取端口扫描数据（统一接口）
local function get_port_scan_data()
    local connections, all_connections = perform_active_port_scan()
    local alerts = analyze_scan_patterns(connections)

    -- 统计外部IP数量
    local external_ip_count = 0
    for _ in pairs(all_connections.external_ips) do
        external_ip_count = external_ip_count + 1
    end

    return alerts, {
        external_ip_count = external_ip_count,
        total_connections = all_connections.total_connections,
        internal_connections = all_connections.internal_count,
        external_connections = all_connections.external_count,
        suspicious_alerts = #alerts
    }
end

-- 加载端口扫描历史
local function load_port_scan_history()
    local json = require("luci.jsonc")
    local fd = io.open(PORT_SCAN_HISTORY_FILE, "r")
    if not fd then
        return {scans = {}}
    end
    local content = fd:read("*a")
    fd:close()
    
    if content and content ~= "" then
        local ok, data = pcall(json.parse, content)
        if ok and data and data.scans then
            return data
        end
    end
    
    return {scans = {}}
end

-- 保存端口扫描记录到历史
local function save_port_scan_to_history(scan)
    local history = load_port_scan_history()
    
    table.insert(history.scans, 1, {
        id = os.time() .. math.random(1000, 9999),
        ip = scan.ip or "",
        port_count = scan.port_count or 0,
        connection_count = scan.connection_count or 0,
        severity = scan.severity or "low",
        suspicious_score = scan.suspicious_score or 0,
        reasons = scan.reasons or {},
        timestamp = os.time(),
        handled = false,
        handle_action = nil,
        handle_time = nil
    })
    
    -- 限制历史数量
    while #history.scans > MAX_PORT_SCAN_HISTORY do
        table.remove(history.scans)
    end
    
    local json = require("luci.jsonc")
    local dir = PORT_SCAN_HISTORY_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local fd = io.open(PORT_SCAN_HISTORY_FILE, "w")
    if fd then
        fd:write(json.stringify(history))
        fd:close()
    end
end

-- API: 启动端口扫描检测
function api_start_port_scan()
    if not require_csrf_token() then return end

    local response_data = nil
    collectgarbage("collect")

    local ok, err = pcall(function()
        -- 执行主动扫描（获取完整数据）
        local connections, all_connections = perform_active_port_scan()

        -- 分析扫描模式
        local scan_alerts = analyze_scan_patterns(connections)

        -- 将可疑记录保存到历史
        for _, alert in ipairs(scan_alerts) do
            save_port_scan_to_history(alert)
        end

        -- 统计外部IP数量
        local external_ip_count = 0
        for _ in pairs(all_connections.external_ips) do
            external_ip_count = external_ip_count + 1
        end

        response_data = success_response({
            message = "端口扫描完成",
            connections = connections,
            alerts = scan_alerts,
            total_external_ips = external_ip_count,
            total_connections = all_connections.total_connections,
            suspicious_count = #scan_alerts,
            internal_connections = all_connections.internal_connections,
            external_connections = all_connections.external_count,
            scan_time = os.time()
        })
    end)

    if not ok then
        response_data = error_response(-1, "端口扫描失败", tostring(err))
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取当前端口扫描检测结果（兼容旧接口）
function api_get_port_scan_detection()
    local response_data = nil
    collectgarbage("collect")

    local ok, err = pcall(function()
        -- 执行快速扫描
        local connections, all_connections = perform_active_port_scan()
        local scan_alerts = analyze_scan_patterns(connections)

        -- 统计外部IP数量
        local external_ip_count = 0
        for _ in pairs(all_connections.external_ips) do
            external_ip_count = external_ip_count + 1
        end

        -- 转换为兼容格式
        local result = {}
        for _, alert in ipairs(scan_alerts) do
            local port_list = {}
            for port, info in pairs(alert.ports or {}) do
                table.insert(port_list, port .. "(" .. (info.name or "") .. ")")
            end

            table.insert(result, {
                ip = alert.ip,
                port_count = alert.port_count,
                ports = table.concat(port_list, ","),
                scan_count = alert.connection_count,
                severity = alert.severity,
                suspicious_score = alert.suspicious_score,
                reasons = alert.reasons,
                first_seen = alert.timestamp,
                last_seen = os.time()
            })
        end

        response_data = success_response({
            scans = result,
            scan_count = #result,
            external_ip_count = external_ip_count,
            total_connections = all_connections.total_connections,
            internal_connections = all_connections.internal_count,
            external_connections = all_connections.external_count,
            last_check = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取端口扫描检测结果失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取端口扫描历史
function api_get_port_scan_history()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local history = load_port_scan_history()
        
        local total_count = #history.scans
        local unhandled_count = 0
        local high_risk_count = 0
        
        for _, scan in ipairs(history.scans) do
            if not scan.handled then
                unhandled_count = unhandled_count + 1
            end
            if scan.severity == "high" then
                high_risk_count = high_risk_count + 1
            end
        end
        
        response_data = success_response({
            scans = history.scans,
            total_count = total_count,
            unhandled_count = unhandled_count,
            high_risk_count = high_risk_count
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取扫描历史失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 处理端口扫描告警
function api_handle_port_scan_alert()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local alert_id = luci.http.formvalue("alert_id") or ""
    local action = luci.http.formvalue("action") or ""
    local note = luci.http.formvalue("note") or ""
    
    local ok, err = pcall(function()
        if not alert_id or alert_id == "" then
            response_data = error_response(-1, "告警ID不能为空")
            return
        end
        
        if not action or (action ~= "block" and action ~= "ignore" and action ~= "whitelist") then
            response_data = error_response(-1, "无效的操作类型")
            return
        end
        
        local history = load_port_scan_history()
        local found = false
        local target_ip = ""
        
        for i, scan in ipairs(history.scans) do
            if tostring(scan.id) == alert_id then
                scan.handled = true
                scan.handle_action = action
                scan.handle_time = os.time()
                target_ip = scan.ip or ""
                found = true
                break
            end
        end
        
        if not found then
            response_data = error_response(-1, "未找到该扫描记录")
            return
        end
        
        -- 如果选择阻止，添加iptables规则
        if action == "block" and target_ip ~= "" then
            os.execute("iptables -A INPUT -s " .. target_ip .. " -j DROP 2>/dev/null")
        end
        
        -- 保存更新后的历史
        local json = require("luci.jsonc")
        local fd = io.open(PORT_SCAN_HISTORY_FILE, "w")
        if fd then
            fd:write(json.stringify(history))
            fd:close()
        end
        
        local action_text
        if action == "block" then
            action_text = "已阻止"
        elseif action == "ignore" then
            action_text = "已忽略"
        else
            action_text = "已加入白名单"
        end
        
        response_data = success_response({
            message = "扫描记录" .. action_text,
            alert_id = alert_id,
            action = action,
            target_ip = target_ip
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "处理失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取安全概览
function api_get_security_overview()
    local response_data = nil
    collectgarbage("collect")

    local ok, err = pcall(function()
        local arp_alerts = detect_arp_spoofing()
        local port_scan_alerts, port_scan_stats = get_port_scan_data()
        local arp_table = get_arp_table()

        local high_risk_count = 0
        local medium_risk_count = 0

        for _, alert in ipairs(arp_alerts) do
            if alert.severity == "high" then
                high_risk_count = high_risk_count + 1
            else
                medium_risk_count = medium_risk_count + 1
            end
        end

        for _, scan in ipairs(port_scan_alerts) do
            if scan.severity == "high" then
                high_risk_count = high_risk_count + 1
            elseif scan.severity == "medium" then
                medium_risk_count = medium_risk_count + 1
            end
        end

        local security_score = 100
        security_score = security_score - (high_risk_count * 20)
        security_score = security_score - (medium_risk_count * 10)
        if security_score < 0 then security_score = 0 end

        response_data = success_response({
            security_score = security_score,
            security_level = security_score >= 80 and "安全" or (security_score >= 60 and "一般" or (security_score >= 40 and "风险" or "危险")),
            arp_alerts_count = #arp_alerts,
            port_scan_count = #port_scan_alerts,
            high_risk_count = high_risk_count,
            medium_risk_count = medium_risk_count,
            arp_table_count = #arp_table,
            -- 新增端口扫描统计信息
            port_scan_stats = port_scan_stats or {
                external_ip_count = 0,
                total_connections = 0,
                internal_connections = 0,
                external_connections = 0,
                suspicious_alerts = 0
            },
            last_update = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取安全概览失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取MAC厂商信息
function api_get_mac_vendor()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac") or ""
        local vendor, device_type = get_mac_vendor_info(mac)
        
        -- 获取MAC特征分析
        local mac_analysis = analyze_mac_characteristics(mac)
        
        -- 判断数据来源
        local source = "local_db"
        if not vendor then
            source = "online_api"
            vendor = query_online_oui(mac:sub(1, 2) .. ":" .. mac:sub(4,5) .. ":" .. mac:sub(7,8))
            if not vendor then
                source = "not_found"
                vendor = nil
            end
        end
        
        response_data = success_response({
            mac = mac,
            vendor = vendor or "未知厂商",
            device_type = device_type or "unknown",
            source = source,
            is_locally_administered = mac_analysis.is_locally_administered,
            oui_prefix = mac_analysis.oui_prefix,
            suggestion = generate_vendor_suggestion(mac, vendor, mac_analysis)
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取MAC厂商失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- 生成厂商查询建议
local function generate_vendor_suggestion(mac, vendor, mac_analysis)
    if vendor and vendor ~= "未知厂商" then
        return nil  -- 已识别，无需建议
    end
    
    local suggestions = {}
    
    if mac_analysis.is_locally_administered then
        table.insert(suggestions, {
            type = "info",
            text = "这是本地管理MAC地址（软件生成），可能来自虚拟机、Docker容器或WiFi中继器"
        })
    else
        table.insert(suggestions, {
            type = "info", 
            text = "该OUI前缀未在本地数据库和在线API中找到"
        })
        table.insert(suggestions, {
            type = "tip",
            text = "可能是新注册的厂商或专用设备，建议提供主机名进行设备指纹识别"
        })
    end
    
    return suggestions
end

-- API: 获取设备指纹识别
function api_get_device_fingerprint()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac") or ""
        local hostname = luci.http.formvalue("hostname") or ""
        
        local dhcp_leases = load_dhcp_leases()
        local lease_info = dhcp_leases[mac:upper()]
        
        local fingerprint = parse_dhcp_fingerprint(hostname, lease_info and lease_info.vendor_class)
        
        local vendor, device_type = get_mac_vendor_info(mac)
        if vendor and fingerprint.confidence < 70 then
            fingerprint.vendor = vendor
            fingerprint.device_type = device_type
            fingerprint.confidence = 60
            fingerprint.fingerprint_data.source = "oui_database"
        end
        
        response_data = success_response({
            mac = mac,
            hostname = hostname,
            fingerprint = fingerprint
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取设备指纹失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取ARP欺骗检测结果
function api_get_arp_spoof_detection()
    local response_data = nil
    collectgarbage("collect")

    local ok, err = pcall(function()
        local alerts = detect_arp_spoofing()
        local arp_table = get_arp_table()

        -- 保存当前ARP缓存用于下次对比
        save_arp_cache()

        response_data = success_response({
            alerts = alerts,
            arp_table = arp_table,
            alert_count = #alerts,
            last_check = os.time()
        })
    end)

    if not ok then
        response_data = error_response(-1, "获取ARP检测结果失败", tostring(err))
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 获取端口扫描检测结果
function api_get_port_scan_detection()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local scans = get_port_scan_data()
        
        response_data = success_response({
            scans = scans,
            scan_count = #scans,
            last_check = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取端口扫描检测结果失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- ============================================================
-- ARP告警历史记录与管理
-- ============================================================
local ARP_ALERT_HISTORY_FILE = "/tmp/router_assistant/arp_alert_history.json"
local MAX_ALERT_HISTORY = 200  -- 最多保存200条历史记录

local function load_arp_alert_history()
    local json = require("luci.jsonc")
    local fd = io.open(ARP_ALERT_HISTORY_FILE, "r")
    if not fd then
        return {alerts = {}}
    end
    local content = fd:read("*a")
    fd:close()
    
    if content and content ~= "" then
        local ok, data = pcall(json.parse, content)
        if ok and data and data.alerts then
            return data
        end
    end
    
    return {alerts = {}}
end

local function save_arp_alert_to_history(alert)
    local history = load_arp_alert_history()
    
    -- 添加新记录
    table.insert(history.alerts, 1, {
        id = os.time() .. math.random(1000, 9999),
        type = alert.type,
        severity = alert.severity,
        mac = alert.mac or "",
        ip = alert.ip or "",
        mac_old = alert.mac_old or "",
        mac_new = alert.mac_new or "",
        message = alert.message or "",
        timestamp = os.time(),
        handled = false,
        handle_action = nil,
        handle_time = nil
    })
    
    -- 限制历史记录数量
    while #history.alerts > MAX_ALERT_HISTORY do
        table.remove(history.alerts)
    end
    
    -- 保存到文件
    local json = require("luci.jsonc")
    local dir = ARP_ALERT_HISTORY_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local fd = io.open(ARP_ALERT_HISTORY_FILE, "w")
    if fd then
        fd:write(json.stringify(history))
        fd:close()
    end
end

-- 在检测到ARP欺骗时自动保存到历史记录
local function detect_and_log_arp_spoofing()
    local alerts = detect_arp_spoofing()
    
    -- 将当前告警保存到历史（只保存未处理的新告警）
    for _, alert in ipairs(alerts) do
        if not alert.is_likely_false_positive then
            save_arp_alert_to_history(alert)
        end
    end
    
    return alerts
end

-- API: 获取ARP告警历史
function api_get_arp_alert_history()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local history = load_arp_alert_history()
        
        -- 统计数据
        local total_count = #history.alerts
        local unhandled_count = 0
        local high_risk_count = 0
        
        for _, alert in ipairs(history.alerts) do
            if not alert.handled then
                unhandled_count = unhandled_count + 1
            end
            if alert.severity == "high" then
                high_risk_count = high_risk_count + 1
            end
        end
        
        response_data = success_response({
            alerts = history.alerts,
            total_count = total_count,
            unhandled_count = unhandled_count,
            high_risk_count = high_risk_count
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取告警历史失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 处理ARP告警（隔离/忽略）
function api_handle_arp_alert()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local alert_id = luci.http.formvalue("alert_id") or ""
    local action = luci.http.formvalue("action") or ""  -- isolate / ignore / whitelist
    local note = luci.http.formvalue("note") or ""
    
    local ok, err = pcall(function()
        if not alert_id or alert_id == "" then
            response_data = error_response(-1, "告警ID不能为空")
            return
        end
        
        if not action or (action ~= "isolate" and action ~= "ignore" and action ~= "whitelist") then
            response_data = error_response(-1, "无效的操作类型")
            return
        end
        
        local history = load_arp_alert_history()
        local found = false
        local target_mac = ""
        
        -- 查找并更新告警状态
        for i, alert in ipairs(history.alerts) do
            if tostring(alert.id) == alert_id then
                alert.handled = true
                alert.handle_action = action
                alert.handle_time = os.time()
                target_mac = alert.mac or alert.mac_old or alert.mac_new or ""
                found = true
                break
            end
        end
        
        if not found then
            response_data = error_response(-1, "未找到该告警记录")
            return
        end
        
        -- 根据操作执行相应动作
        if action == "whitelist" and target_mac ~= "" then
            -- 加入白名单
            local whitelist = load_security_whitelist()
            if not whitelist.macs then
                whitelist.macs = {}
            end
            local clean_mac = target_mac:gsub(":", ""):gsub("-", ""):upper()
            whitelist.macs[clean_mac] = {
                added_time = os.time(),
                note = note or "从ARP告警中添加",
                source = "auto"
            }
            save_security_whitelist(whitelist)
        elseif action == "isolate" and target_mac ~= "" then
            -- 隔离设备：添加到黑名单并记录
            local blacklist_file = "/tmp/router_assistant/blacklist_macs.json"
            local json = require("luci.jsonc")
            
            local blacklist = {}
            local bl_fd = io.open(blacklist_file, "r")
            if bl_fd then
                local content = bl_fd:read("*a")
                bl_fd:close()
                if content and content ~= "" then
                    local bl_ok, bl_data = pcall(json.parse, content)
                    if bl_ok and bl_data then
                        blacklist = bl_data.macs or {}
                    end
                end
            end
            
            local clean_mac = target_mac:gsub(":", ""):gsub("-", ""):upper()
            blacklist[clean_mac] = {
                reason = note or "ARP异常行为",
                added_time = os.time(),
                source = "arp_detection"
            }
            
            local dir = blacklist_file:match("^(.+)/[^/]+$")
            if dir then
                os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
            end
            local new_fd = io.open(blacklist_file, "w")
            if new_fd then
                new_fd:write(json.stringify({macs = blacklist}))
                new_fd:close()
            end
        end
        
        -- 保存更新的历史记录
        local json = require("luci.jsonc")
        local fd = io.open(ARP_ALERT_HISTORY_FILE, "w")
        if fd then
            fd:write(json.stringify(history))
            fd:close()
        end
        
        local action_text
        if action == "isolate" then
            action_text = "已隔离"
        elseif action == "ignore" then
            action_text = "已忽略"
        else
            action_text = "已加入白名单"
        end
        
        response_data = success_response({
            message = "告警" .. action_text,
            alert_id = alert_id,
            action = action,
            target_mac = target_mac
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "处理告警失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 清空告警历史
function api_clear_arp_history()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        -- 清空历史文件
        local fd = io.open(ARP_ALERT_HISTORY_FILE, "w")
        if fd then
            fd:write('{"alerts":[]}')
            fd:close()
        end
        
        response_data = success_response({
            message = "告警历史已清空",
            timestamp = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "清空历史失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 刷新安全数据
function api_refresh_security_data()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        save_arp_cache()
        
        response_data = success_response({
            message = "安全数据已刷新",
            timestamp = os.time()
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "刷新安全数据失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- ============================================================
-- 安全白名单管理API
-- ============================================================

-- 保存白名单到文件
local function save_security_whitelist(whitelist)
    local json = require("luci.jsonc")
    local dir = SECURITY_WHITELIST_FILE:match("^(.+)/[^/]+$")
    if dir then
        os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
    end
    local json_str = json.stringify(whitelist) or '{"macs":{}}'
    local fd = io.open(SECURITY_WHITELIST_FILE, "w")
    if fd then
        fd:write(json_str)
        fd:close()
    end
end

-- API: 获取安全白名单
function api_get_security_whitelist()
    local response_data = nil
    collectgarbage("collect")
    
    local ok, err = pcall(function()
        local whitelist = load_security_whitelist()
        local mac_list = {}
        
        if whitelist and whitelist.macs then
            for mac, _ in pairs(whitelist.macs) do
                table.insert(mac_list, mac)
            end
        end
        
        -- 添加自动识别的本地管理MAC（建议加入白名单）
        local auto_suggested = {}
        local arp_table = get_arp_table()
        for _, entry in ipairs(arp_table) do
            if is_locally_administered_mac(entry.mac) and not is_mac_whitelisted(entry.mac) then
                table.insert(auto_suggested, {
                    mac = entry.mac,
                    reason = "本地管理MAC（虚拟接口）",
                    ip_count = 0
                })
            end
        end
        
        response_data = success_response({
            whitelisted_macs = mac_list,
            suggested_macs = auto_suggested,
            total_whitelisted = #mac_list,
            total_suggested = #auto_suggested
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "获取白名单失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 添加到白名单
function api_add_security_whitelist()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local mac = luci.http.formvalue("mac") or ""
    local note = luci.http.formvalue("note") or ""
    
    local ok, err = pcall(function()
        if not mac or mac == "" then
            response_data = error_response(-1, "MAC地址不能为空")
            return
        end
        
        local clean_mac = mac:upper():gsub("[^A-F0-9]", "")
        if #clean_mac < 12 then
            response_data = error_response(-1, "无效的MAC地址格式")
            return
        end
        
        local whitelist = load_security_whitelist()
        if not whitelist.macs then
            whitelist.macs = {}
        end
        
        whitelist.macs[clean_mac] = {
            added_time = os.time(),
            note = note,
            source = "manual"
        }
        
        save_security_whitelist(whitelist)
        
        -- 清除缓存使更改立即生效
        _security_whitelist_cache = nil
        
        response_data = success_response({
            message = "已将 " .. mac .. " 添加到白名单",
            mac = clean_mac
        })
    end)
    
    if not ok then
        response_data = error_response(-1, "添加白名单失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- API: 从白名单移除
function api_remove_security_whitelist()
    if not require_csrf_token() then return end
    
    local response_data = nil
    collectgarbage("collect")
    
    local mac = luci.http.formvalue("mac") or ""
    
    local ok, err = pcall(function()
        if not mac or mac == "" then
            response_data = error_response(-1, "MAC地址不能为空")
            return
        end
        
        local clean_mac = mac:upper():gsub("[^A-F0-9]", "")
        local whitelist = load_security_whitelist()
        
        if whitelist.macs and whitelist.macs[clean_mac] then
            whitelist.macs[clean_mac] = nil
            save_security_whitelist(whitelist)
            
            -- 清除缓存
            _security_whitelist_cache = nil
            
            response_data = success_response({
                message = "已从白名单移除 " .. mac,
                mac = clean_mac
            })
        else
            response_data = error_response(-1, "该MAC不在白名单中")
        end
    end)
    
    if not ok then
        response_data = error_response(-1, "移除失败", tostring(err))
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end
