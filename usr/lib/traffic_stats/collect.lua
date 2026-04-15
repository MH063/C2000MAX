#!/usr/bin/lua

local fs = require "nixio.fs"

-- ========== 内置 JSON 实现（不依赖外部模块，解决 require('json') 找不到的问题） ==========
-- OpenWrt 环境下没有独立的 json 模块，luci.jsonc 需要 LuCI 上下文
-- 此实现提供足够的 JSON 编解码功能供流量采集使用
local json = {}

-- 简单的 JSON 编码（支持 string, number, boolean, nil, table）
function json.encode(data)
    local t = type(data)
    if t == "nil" then return "null"
    elseif t == "boolean" then return data and "true" or "false"
    elseif t == "number" then
        if data ~= data then return "null" end -- NaN
        if math.abs(data) == math.huge then return "null" end -- Inf
        return tostring(data)
    elseif t == "string" then
        -- 转义特殊字符
        local s = data:gsub('[%z\1-\31\\"]', function(c)
            local codes = {
                ['"'] = '\\"', ['\\'] = "\\\\",
                ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
            }
            return codes[c] or ('\\u%04x'):format(c:byte())
        end)
        return '"' .. s .. '"'
    elseif t == "table" then
        local is_array = true
        local max_idx = 0
        for k, _ in pairs(data) do
            if type(k) ~= "number" or k < 1 or math.floor(k) ~= k then
                is_array = false
                break
            end
            if k > max_idx then max_idx = k end
        end

        if is_array and #data > 0 then
            local parts = {}
            for i = 1, #data do
                parts[i] = json.encode(data[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local parts = {}
            for k, v in pairs(data) do
                table.insert(parts, '"' .. tostring(k) .. '":' .. json.encode(v))
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    else
        return '"[unsupported:' .. t .. ']"'
    end
end

-- 简单的 JSON 解码（足够解析流量统计数据格式）
function json.decode(str)
    if not str or type(str) ~= "string" or str == "" then
        return nil, "empty input"
    end

    local pos = 1
    local len = #str

    -- 跳过空白字符
    local function skip_whitespace()
        while pos <= len do
            local c = str:sub(pos, pos)
            if c == ' ' or c == '\t' or c == '\n' or c == '\r' then
                pos = pos + 1
            else
                break
            end
        end
    end

    -- 解析值
    local function parse_value()
        skip_whitespace()
        if pos > len then return nil, "unexpected end" end

        local c = str:sub(pos, pos)

        if c == '{' then return parse_object2()
        elseif c == '[' then return parse_array()
        elseif c == '"' then return parse_string()
        elseif c == 't' then return parse_literal("true", true)
        elseif c == 'f' then return parse_literal("false", false)
        elseif c == 'n' then return parse_literal("null", nil)
        elseif c == '-' or c:match('%d') then return parse_number()
        else
            return nil, "unexpected char: " .. c .. " at pos " .. pos
        end
    end

    -- 解析对象
    local function parse_object()
        pos = pos + 1 -- skip '{'
        local obj = {}
        skip_whitespace()
        if str:sub(pos, pos) == '}' then
            pos = pos + 1
            return obj
        end
        while true do
            skip_whitespace()
            local key = parse_string()
            if not key then return nil, "expected key" end
            skip_whitespace()
            if str:sub(pos, pos) ~= ':' then return nil, "expected : at pos " .. pos end
            pos = pos + 1
            local val = parse_value()
            if val == nil and type(parse_value()) ~= "nil" then -- allow null values
                -- null is fine
            end
            -- Re-parse to get actual value including null
            -- Actually we need to handle this differently
            -- Let me restructure...
            break -- will fix below
        end
        return obj
    end

    -- 重写更健壮的解析器
    local function parse_object2()
        pos = pos + 1 -- skip '{'
        local obj = {}
        skip_whitespace()
        if pos <= len and str:sub(pos, pos) == '}' then
            pos = pos + 1
            return obj
        end
        while true do
            skip_whitespace()
            if pos > len then return nil, "unclosed object" end
            local key = parse_string()
            if not key then return nil, "expected object key" end
            skip_whitespace()
            if pos > len or str:sub(pos, pos) ~= ':' then return nil, "expected ':'" end
            pos = pos + 1
            local val = parse_value()
            obj[key] = val
            skip_whitespace()
            if pos > len then return nil, "unclosed object" end
            local c = str:sub(pos, pos)
            if c == '}' then pos = pos + 1; return obj
            elseif c == ',' then pos = pos + 1
            else return nil, "expected ',' or '}'"
            end
        end
    end

    -- 解析数组
    local function parse_array()
        pos = pos + 1 -- skip '['
        local arr = {}
        skip_whitespace()
        if pos <= len and str:sub(pos, pos) == ']' then
            pos = pos + 1
            return arr
        end
        while true do
            local val = parse_value()
            arr[#arr + 1] = val
            skip_whitespace()
            if pos > len then return nil, "unclosed array" end
            local c = str:sub(pos, pos)
            if c == ']' then pos = pos + 1; return arr
            elseif c == ',' then pos = pos + 1
            else return nil, "expected ',' or ']'"
            end
        end
    end

    -- 解析字符串
    local function parse_string()
        if str:sub(pos, pos) ~= '"' then return nil, "expected '\"'" end
        pos = pos + 1
        local result = {}
        while pos <= len do
            local c = str:sub(pos, pos)
            if c == '"' then
                pos = pos + 1
                return table.concat(result)
            elseif c == '\\' then
                pos = pos + 1
                if pos > len then return nil, "unterminated escape" end
                local esc = str:sub(pos, pos)
                local escapes = {
                    ['"'] = '"', ['\\'] = '\\', ['/'] = '/',
                    ['n'] = '\n', ['r'] = '\r', ['t'] = '\t', ['b'] = '\b', ['f'] = '\f',
                }
                if esc == 'u' then
                    -- Unicode escape (simplified: only handle basic BMP)
                    pos = pos + 1
                    local hex = str:sub(pos, pos + 3):lower()
                    if hex:match('^[%da-f]+$') then
                        result[#result + 1] = string.char(tonumber(hex, 16))
                        pos = pos + 4
                    else
                        result[#result + 1] = '?'
                    end
                else
                    result[#result + 1] = escapes[esc] or esc
                    pos = pos + 1
                end
            else
                result[#result + 1] = c
                pos = pos + 1
            end
        end
        return nil, "unterminated string"
    end

    -- 解析数字
    local function parse_number()
        local start = pos
        if str:sub(pos, pos) == '-' then pos = pos + 1 end
        while pos <= len and str:sub(pos, pos):match('%d') do
            pos = pos + 1
        end
        if pos <= len and str:sub(pos, pos) == '.' then
            pos = pos + 1
            while pos <= len and str:sub(pos, pos):match('%d') do
                pos = pos + 1
            end
        end
        if pos <= len and str:sub(pos, pos):match('[eE]') then
            pos = pos + 1
            if pos <= len and str:sub(pos, pos):match('[+-]') then
                pos = pos + 1
            end
            while pos <= len and str:sub(pos, pos):match('%d') do
                pos = pos + 1
            end
        end
        local num_str = str:sub(start, pos - 1)
        local n = tonumber(num_str)
        if not n then return nil, "invalid number: " .. num_str end
        return n
    end

    -- 解析字面量
    local function parse_literal(expected, value)
        local end_pos = pos + #expected
        if str:sub(pos, end_pos) == expected then
            pos = end_pos
            return value
        end
        return nil, "expected '" .. expected .. "'"
    end

    -- 替换函数引用
    parse_object = parse_object2

    local result = parse_value()
    return result
end

-- ========== 存储路径配置（与 router_assistant.lua 保持一致） ==========
-- 数据目录名
local DATA_DIR_NAME = "router_assistant"

-- 存储路径优先级：TF卡优先，其次内存
local STORAGE_BASE_PATHS = {
    "/tmp/storage/mmcblk0p1",
    "/mnt/mmcblk0p1",
    "/mnt/sdcard",
    "/tmp/mnt/mmcblk0p1",
    "/overlay"
}

-- 缓存
local _cached_storage_path = nil
local _storage_path_cache_time = 0
local STORAGE_CACHE_TTL = 3600  -- 1小时

local function log(msg)
    os.execute("logger -t traffic-collect '" .. msg .. "' 2>/dev/null")
end

-- 获取可写的存储路径（与主控制器逻辑一致）
local function get_data_dir()
    local current_time = os.time()

    -- 使用缓存
    if _cached_storage_path and (current_time - _storage_path_cache_time) < STORAGE_CACHE_TTL then
        return _cached_storage_path
    end

    -- 检查每个候选路径
    for _, base_path in ipairs(STORAGE_BASE_PATHS) do
        local data_dir = base_path .. "/" .. DATA_DIR_NAME
        -- 确保目录存在
        os.execute("mkdir -p '" .. data_dir .. "' 2>/dev/null")
        -- 测试写入权限
        local test_file = data_dir .. "/.write_test"
        local fd = io.open(test_file, "w")
        if fd then
            fd:close()
            os.remove(test_file)
            _cached_storage_path = data_dir
            _storage_path_cache_time = current_time
            log("Storage path: " .. data_dir .. " (persistent)")
            return data_dir
        end
    end

    -- 回退到内存目录
    local fallback_dir = "/tmp/" .. DATA_DIR_NAME
    os.execute("mkdir -p '" .. fallback_dir .. "' 2>/dev/null")
    _cached_storage_path = fallback_dir
    _storage_path_cache_time = current_time
    log("Storage path: " .. fallback_dir .. " (memory, volatile)")
    return fallback_dir
end

local function getDate()
    return os.date("%Y-%m-%d")
end

local function getWeek()
    local t = os.date("*t")
    local year = t.year
    local week = os.date("%W")
    return string.format("%d-W%s", year, week)
end

local function getMonth()
    return os.date("%Y-%m")
end

local function mkdir(dir)
    os.execute("mkdir -p " .. dir .. " 2>/dev/null")
end

local function saveJson(file, data)
    mkdir(file:match("^(.+)/[^/]+$") or ".")
    local f = io.open(file, "w")
    if f then
        f:write(json.encode(data))
        f:close()
        return true
    end
    return false
end

local function loadJson(file)
    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and content ~= "" then
            local ok, data = pcall(json.decode, content)
            if ok then return data end
        end
    end
    return nil
end

local function exec(cmd)
    local f = io.popen(cmd .. " 2>/dev/null")
    if f then
        local result = f:read("*all")
        f:close()
        return result
    end
    return ""
end

local function getIpsetStats(ipset_name)
    local stats = {}
    local output = exec("ipset list " .. ipset_name .. " 2>/dev/null")
    if not output or output == "" then
        log("WARNING: ipset " .. ipset_name .. " has no output")
        return stats
    end

    -- ipset 输出格式（带 counters 时）：
    -- Name: traffic_stats_rx
    -- Type: hash:mac
    -- Revision: 0
    -- Header: hashsize 1024 maxelem 65536 counters
    -- Size in memory: 1224
    -- References: 7
    -- Number of entries: 8
    -- Members:
    -- 00:93:37:CD:72:F1 packets 0 bytes 0
    -- 5E:42:94:69:1C:02 packets 0 bytes 0
    --
    -- 注意：ipset 用 "bytes" 而非 "bytes:"，即 "bytes 123" 而非 "bytes:123"
    for line in output:gmatch("[^\r\n]+") do
        -- MAC 地址行：行首为两个十六进制字符 + 冒号开头（如 "00:93:37:CD:72:F1 packets 0 bytes 0"）
        if line:match("^[0-9a-fA-F][0-9a-fA-F]:") then
            local mac = line:match("^([0-9a-fA-F:]+)")
            if mac then
                -- 尝试提取 bytes：格式是 "bytes <number>" 或 "bytes:<number>"
                local bytes = nil
                if line:match("bytes%s+%d+") then
                    bytes = line:match("bytes%s+(%d+)")
                elseif line:match("bytes:%d+") then
                    bytes = line:match("bytes:(%d+)")
                end
                if bytes then
                    stats[mac] = tonumber(bytes) or 0
                end
            end
        end
    end

    -- 调试：统计有多少 MAC 被解析出来
    local count = 0
    for _ in pairs(stats) do count = count + 1 end
    print("DEBUG: ipset " .. ipset_name .. " parsed " .. count .. " entries")
    log("DEBUG: ipset " .. ipset_name .. " parsed " .. count .. " entries")
    return stats
end

local function saveToFile(dir, key, data, backup_dir)
    mkdir(dir)
    local file = dir .. "/" .. key .. ".json"
    local existing = loadJson(file) or {}
    for mac, value in pairs(data) do
        if not existing[mac] then
            existing[mac] = {rx = 0, tx = 0, last_update = 0}
        end
        existing[mac].rx = (existing[mac].rx or 0) + (value.rx or 0)
        existing[mac].tx = (existing[mac].tx or 0) + (value.tx or 0)
        existing[mac].last_update = os.time()
    end
    saveJson(file, existing)

    if backup_dir then
        local backup_file = backup_dir .. "/" .. key .. ".json.bak"
        mkdir(backup_dir)
        saveJson(backup_file, existing)
    end
end

local function loadDeviceNames()
    local names = {}
    local lease_file = "/tmp/dhcp.leases"
    if fs.access(lease_file) then
        for line in io.lines(lease_file) do
            local fields = {}
            for w in line:gmatch("%S+") do
                table.insert(fields, w)
            end
            if #fields >= 5 then
                local mac = fields[2]:upper()
                local hostname = fields[5]
                if hostname then
                    hostname = hostname:gsub("\\(%d%d%d)", function(o)
                        return string.char(tonumber(o))
                    end)
                end
                names[mac] = hostname or "未知"
            end
        end
    end
    return names
end

local IPSET_RX = "traffic_stats_rx"
local IPSET_TX = "traffic_stats_tx"

-- 从 /sys/class/net/ 读取网络接口的字节统计（绕过 iptables/ipset 匹配问题）
-- 返回 {rx = bytes, tx = bytes} 或 nil
local function getInterfaceStats(iface)
    local rx = 0
    local tx = 0
    local f = io.open("/sys/class/net/" .. iface .. "/statistics/rx_bytes", "r")
    if f then
        local v = f:read("*n")
        f:close()
        rx = v or 0
    end
    f = io.open("/sys/class/net/" .. iface .. "/statistics/tx_bytes", "r")
    if f then
        local v = f:read("*n")
        f:close()
        tx = v or 0
    end
    return rx, tx
end

-- 自动检测 WAN 接口（排除 lan/wifi/bridge 类接口）
local function detectWanIfaces()
    local wan = {}
    local lan_patterns = {["br-lan"] = true, ["ra0"] = true, ["rai0"] = true,
                          ["apcli0"] = true, ["apclii0"] = true, ["lo"] = true}
    local dir = io.popen("ls /sys/class/net/ 2>/dev/null")
    if dir then
        for iface in dir:lines() do
            if not lan_patterns[iface] and iface:match("^eth") then
                table.insert(wan, iface)
            end
        end
        dir:close()
    end
    -- fallback：至少尝试 eth0
    if #wan == 0 then table.insert(wan, "eth0") end
    return wan
end

local function collectTraffic()
    print("Starting traffic collection...")
    log("Starting traffic collection...")

    -- 动态获取存储目录
    local base_dir = get_data_dir()
    local data_file = base_dir .. "/current.json"
    local daily_dir = base_dir .. "/daily"
    local weekly_dir = base_dir .. "/weekly"
    local monthly_dir = base_dir .. "/monthly"
    local backup_dir = base_dir .. "/backup"

    mkdir(base_dir)
    mkdir(daily_dir)
    mkdir(weekly_dir)
    mkdir(monthly_dir)
    mkdir(backup_dir)

    -- ===== 方案A：直接读取 /sys/class/net/ WAN接口字节统计 =====
    -- 不依赖 iptables/ipset 匹配，避免 nRadio 平台 mangle RX 不计数的 bug
    local wan_ifaces = detectWanIfaces()
    local total_wan_rx, total_wan_tx = 0, 0
    local wan_iface_for_baseline = wan_ifaces[1] or "eth1"
    for _, iface in ipairs(wan_ifaces) do
        local r, t = getInterfaceStats(iface)
        total_wan_rx = total_wan_rx + r
        total_wan_tx = total_wan_tx + t
        print("DEBUG: iface " .. iface .. " rx=" .. tostring(r) .. " tx=" .. tostring(t))
    end

    -- ===== 基准值机制：purge 后从零开始 =====
    -- 如果有基准值（purge_data 时记录），则计算增量而非累计值
    -- 这样 purge 后页面显示的就是 purge 后的增量，而不是系统开机以来的总流量
    local baseline_file = base_dir .. "/baseline.json"
    local baseline = loadJson(baseline_file)
    if baseline then
        local primary_iface = baseline.iface or wan_iface_for_baseline
        local primary_rx, primary_tx = getInterfaceStats(primary_iface)

        -- 检测计数器重置（路由器重启后接口计数器从 0 开始）
        -- 如果当前值 < 基准值，说明接口重启或计数器被清零，需要重新初始化基准
        if primary_rx < (baseline.rx or 0) or primary_tx < (baseline.tx or 0) then
            -- 重新初始化基准值为当前值（重启后第一个采集周期作为新基准）
            saveJson(baseline_file, {iface = primary_iface, rx = primary_rx, tx = primary_tx, time = os.time(), rebooted = true})
            print("DEBUG: baseline reinitialized after reboot/reject: iface=" .. primary_iface ..
                  " old_base_rx=" .. tostring(baseline.rx) .. " current_rx=" .. tostring(primary_rx))
            baseline.rx = primary_rx
            baseline.tx = primary_tx
        end

        -- 计算相对于基准的增量
        local delta_rx = math.max(0, primary_rx - (baseline.rx or 0))
        local delta_tx = math.max(0, primary_tx - (baseline.tx or 0))
        print("DEBUG: baseline active: iface=" .. primary_iface ..
              " base_rx=" .. tostring(baseline.rx) .. " current_rx=" .. tostring(primary_rx) ..
              " delta_rx=" .. tostring(delta_rx))
        -- 用增量替换总量，后续按比例分配
        total_wan_rx = delta_rx
        total_wan_tx = delta_tx
    else
        -- 无基准值（首次安装），初始化基准值
        -- 这样下次 purge 后可以正确从零开始
        local primary_iface = wan_iface_for_baseline
        local primary_rx, primary_tx = getInterfaceStats(primary_iface)
        saveJson(baseline_file, {iface = primary_iface, rx = primary_rx, tx = primary_tx, time = os.time()})
        print("DEBUG: baseline initialized: iface=" .. primary_iface ..
              " rx=" .. tostring(primary_rx) .. " tx=" .. tostring(primary_tx))
    end

    -- ===== 方案B：从 ipset 获取每设备 TX 数据（仍然工作） =====
    -- TX 方向（LAN→WAN）通过 br-lan 入接口匹配 src MAC，完全正常
    local tx_stats = getIpsetStats(IPSET_TX)
    local tx_count = 0
    for _ in pairs(tx_stats) do tx_count = tx_count + 1 end
    print("DEBUG: tx_stats from ipset: " .. tx_count .. " devices")

    -- ===== 按设备分配 WAN 总流量 =====
    -- TX 比例 × WAN 总流量 = 估算的每设备 RX
    -- 原理：TCP 下行流量与上行流量自然相关（请求→响应）
    local current = loadJson(data_file) or {}
    local names = loadDeviceNames()

    -- 计算当前 TX 总量
    local total_tx = 0
    for mac, v in pairs(tx_stats) do total_tx = total_tx + v end

    -- 按 TX 比例分配 RX 给各设备
    local combined = {}
    for mac, tx_bytes in pairs(tx_stats) do
        local rx_estimate = 0
        if total_tx > 0 then
            rx_estimate = math.floor((tx_bytes / total_tx) * total_wan_rx)
        end
        combined[mac] = {rx = rx_estimate, tx = tx_bytes}
    end

    -- 归一化 RX 总和 = WAN 总 RX（避免舍入误差）
    local allocated_rx = 0
    for mac, data in pairs(combined) do
        allocated_rx = allocated_rx + data.rx
    end
    local rx_diff = total_wan_rx - allocated_rx
    -- 把差值加到 TX 最大的设备上（归一化）
    if rx_diff > 0 and total_tx > 0 then
        local top_mac, top_tx = nil, 0
        for mac, tx in pairs(tx_stats) do
            if tx > top_tx then top_tx = tx; top_mac = mac end
        end
        if top_mac then combined[top_mac].rx = combined[top_mac].rx + rx_diff end
    end

    -- 写入历史
    for mac, stats in pairs(combined) do
        local prev = current[mac] or {rx = 0, tx = 0}
        local delta_rx = math.max(0, stats.rx - prev.rx)
        local delta_tx = math.max(0, stats.tx - prev.tx)

        if delta_rx > 0 or delta_tx > 0 then
            saveToFile(daily_dir, getDate(), {[mac] = {rx = delta_rx, tx = delta_tx}}, backup_dir)
            saveToFile(weekly_dir, getWeek(), {[mac] = {rx = delta_rx, tx = delta_tx}}, backup_dir)
            saveToFile(monthly_dir, getMonth(), {[mac] = {rx = delta_rx, tx = delta_tx}}, backup_dir)
        end
    end

    saveJson(data_file, combined)

    -- ===== 保存或更新月度流量快照 =====
    -- 每月第一天自动重置基准
    -- 注意：collect.lua 使用独立的 traffic_monthly_collect.json，避免与 router_assistant.lua 的 traffic_monthly_router.json 冲突
    local monthly_file = base_dir .. "/traffic_monthly_collect.json"
    local monthly_data = loadJson(monthly_file) or {}
    local current_month_key = getMonth()

    -- 检查是否需要初始化新月度快照
    if not monthly_data.last_month or monthly_data.last_month ~= current_month_key then
        -- 新月份：用 combined（当前每设备累计值）作为本月起点基准
        monthly_data[current_month_key] = {}
        for mac, stats in pairs(combined) do
            monthly_data[current_month_key][mac] = {
                rx_start = stats.rx,
                tx_start = stats.tx,
                created_at = os.time()
            }
        end
        monthly_data.last_month = current_month_key
        saveJson(monthly_file, monthly_data)
        -- 修复：#combined 只对数组有效，combined 是哈希表需手动计数
        local dev_count = 0
        for _ in pairs(combined) do dev_count = dev_count + 1 end
        local msg2 = "Monthly snapshot created for " .. current_month_key .. " with " .. dev_count .. " devices"
        print(msg2)
        log(msg2)
    end

    local msg = string.format(
        "Traffic collected: WAN total RX=%.2f MB, TX=%.2f MB | %d devices tracked via ipset TX",
        total_wan_rx / 1024 / 1024, total_wan_tx / 1024 / 1024, tx_count)
    print(msg)
    log(msg)

    return combined
end

local function resetCounters()
    log("Resetting ipset counters...")
    exec("ipset flush " .. IPSET_RX)
    exec("ipset flush " .. IPSET_TX)
    exec("ipset -A " .. IPSET_RX .. " 00:00:00:00:00:00 2>/dev/null; ipset -D " .. IPSET_RX .. " 00:00:00:00:00:00 2>/dev/null; true")
    exec("ipset -A " .. IPSET_TX .. " 00:00:00:00:00:00 2>/dev/null; ipset -D " .. IPSET_TX .. " 00:00:00:00:00:00 2>/dev/null; true")
end

local function getHistory(period, limit)
    local base_dir = get_data_dir()
    local dir = base_dir .. "/daily"
    if period == "weekly" then dir = base_dir .. "/weekly"
    elseif period == "monthly" then dir = base_dir .. "/monthly" end

    local files = {}
    local handle = io.popen("ls -t " .. dir .. "/*.json 2>/dev/null | head -" .. (limit or 30))
    if handle then
        for line in handle:lines() do
            local name = line:match("([^/]+)%.json$")
            if name then
                table.insert(files, name)
            end
        end
        handle:close()
    end
    return files
end

local function getStatsForPeriod(period, key)
    local base_dir = get_data_dir()
    local dir = base_dir .. "/daily"
    if period == "weekly" then dir = base_dir .. "/weekly"
    elseif period == "monthly" then dir = base_dir .. "/monthly" end

    local file = dir .. "/" .. key .. ".json"
    local data = loadJson(file)
    if not data then return {} end

    local names = loadDeviceNames()
    local result = {}
    for mac, stats in pairs(data) do
        table.insert(result, {
            mac = mac,
            hostname = names[mac] or "未知",
            rx = stats.rx or 0,
            tx = stats.tx or 0,
            total = (stats.rx or 0) + (stats.tx or 0),
            last_update = stats.last_update or 0
        })
    end
    table.sort(result, function(a, b) return a.total > b.total end)
    return result
end

local function cleanOld(keep_days)
    keep_days = keep_days or 90
    local base_dir = get_data_dir()
    log("Cleaning data older than " .. keep_days .. " days...")
    os.execute("find " .. base_dir .. "/daily -name '*.json' -mtime +" .. keep_days .. " -delete 2>/dev/null")
    os.execute("find " .. base_dir .. "/weekly -name '*.json' -mtime +" .. (keep_days * 4) .. " -delete 2>/dev/null")
    os.execute("find " .. base_dir .. "/monthly -name '*.json' -mtime +365 -delete 2>/dev/null")
end

local function showHelp()
    print([[
Traffic Stats Collector - Usage:
    lua /usr/lib/traffic_stats/collect.lua <command> [options]

Commands:
    collect         Collect current traffic and save to history
    reset           Reset ipset counters
    history <n>     Show last N history entries
    stats <period> [key]  Show stats for period (daily/weekly/monthly)
                         If key not specified, shows list
    clean [days]    Clean data older than specified days (default: 90)

Examples:
    lua /usr/lib/traffic_stats/collect.lua collect
    lua /usr/lib/traffic_stats/collect.lua stats daily
    lua /usr/lib/traffic_stats/collect.lua stats daily 2024-01-15
    lua /usr/lib/traffic_stats/collect.lua stats weekly 2024-W03
    lua /usr/lib/traffic_stats/collect.lua clean 30
]])
end

local cmd = arg and arg[1] or nil

if not cmd then
    showHelp()
    os.exit(1)
end

if cmd == "collect" then
    collectTraffic()
elseif cmd == "reset" then
    resetCounters()
elseif cmd == "history" then
    local limit = tonumber(arg[2]) or 30
    print("Daily:", table.concat(getHistory("daily", limit), ", "))
    print("Weekly:", table.concat(getHistory("weekly", limit), ", "))
    print("Monthly:", table.concat(getHistory("monthly", limit), ", "))
elseif cmd == "stats" then
    local period = arg[2] or "daily"
    local key = arg[3]
    if key then
        local stats = getStatsForPeriod(period, key)
        print(string.format("%-20s %-15s %12s %12s %12s", "MAC", "Hostname", "Receive", "Send", "Total"))
        print(string.rep("-", 80))
        for _, s in ipairs(stats) do
            print(string.format("%-20s %-15s %12s %12s %12s",
                s.mac, s.hostname,
                string.format("%.2f MB", s.rx / 1024 / 1024),
                string.format("%.2f MB", s.tx / 1024 / 1024),
                string.format("%.2f MB", s.total / 1024 / 1024)))
        end
    else
        print("Available " .. period .. " data:")
        print(table.concat(getHistory(period, 10), "\n"))
    end
elseif cmd == "clean" then
    local days = tonumber(arg[2]) or 90
    cleanOld(days)
elseif cmd == "help" then
    showHelp()
else
    print("Unknown command: " .. cmd)
    showHelp()
    os.exit(1)
end
