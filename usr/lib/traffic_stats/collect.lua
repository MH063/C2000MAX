#!/usr/bin/lua

local fs = require "nixio.fs"
local util = require "luci.util"
local json = require "json"

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
    if not output or output == "" then return stats end

    local current_mac = nil
    for line in output:gmatch("[^\r\n]+") do
        if line:match("^[0-9a-fA-F][0-9a-fA-F]:") then
            current_mac = line:match("^([0-9a-fA-F:]+)")
        elseif current_mac and line:match("bytes:") then
            local bytes = line:match("bytes:(%d+)")
            if bytes then
                stats[current_mac] = tonumber(bytes) or 0
            end
        end
    end
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

local function collectTraffic()
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

    local rx_stats = getIpsetStats(IPSET_RX)
    local tx_stats = getIpsetStats(IPSET_TX)

    local current = loadJson(data_file) or {}
    local names = loadDeviceNames()

    local combined = {}
    for mac, rx in pairs(rx_stats) do
        combined[mac] = {rx = rx, tx = tx_stats[mac] or 0}
    end
    for mac, tx in pairs(tx_stats) do
        if not combined[mac] then
            combined[mac] = {rx = 0, tx = tx}
        end
    end

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

    local total_rx, total_tx = 0, 0
    for mac, stats in pairs(combined) do
        total_rx = total_rx + stats.rx
        total_tx = total_tx + stats.tx
    end

    log(string.format("Traffic collected: RX=%.2f MB, TX=%.2f MB",
        total_rx / 1024 / 1024, total_tx / 1024 / 1024))

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
