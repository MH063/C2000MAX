#!/usr/bin/lua

local fs = require "nixio.fs"
local util = require "luci.util"
local json = require "json"

local DATA_DIR = "/tmp/traffic_stats"
local DATA_FILE = DATA_DIR .. "/current.json"
local DAILY_DIR = DATA_DIR .. "/daily"
local WEEKLY_DIR = DATA_DIR .. "/weekly"
local MONTHLY_DIR = DATA_DIR .. "/monthly"
local BACKUP_DIR = DATA_DIR .. "/backup"

local IPSET_RX = "traffic_stats_rx"
local IPSET_TX = "traffic_stats_tx"

local function log(msg)
    os.execute("logger -t traffic-collect '" .. msg .. "' 2>/dev/null")
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

local function saveToFile(dir, key, data)
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

    local backup_file = BACKUP_DIR .. "/" .. key .. ".json.bak"
    mkdir(BACKUP_DIR)
    saveJson(backup_file, existing)
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

local function collectTraffic()
    log("Starting traffic collection...")

    mkdir(DATA_DIR)
    mkdir(DAILY_DIR)
    mkdir(WEEKLY_DIR)
    mkdir(MONTHLY_DIR)
    mkdir(BACKUP_DIR)

    local rx_stats = getIpsetStats(IPSET_RX)
    local tx_stats = getIpsetStats(IPSET_TX)

    local current = loadJson(DATA_FILE) or {}
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
            saveToFile(DAILY_DIR, getDate(), {[mac] = {rx = delta_rx, tx = delta_tx}})
            saveToFile(WEEKLY_DIR, getWeek(), {[mac] = {rx = delta_rx, tx = delta_tx}})
            saveToFile(MONTHLY_DIR, getMonth(), {[mac] = {rx = delta_rx, tx = delta_tx}})
        end
    end

    saveJson(DATA_FILE, combined)

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
    local dir = DAILY_DIR
    if period == "weekly" then dir = WEEKLY_DIR
    elseif period == "monthly" then dir = MONTHLY_DIR end

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
    local dir = DAILY_DIR
    if period == "weekly" then dir = WEEKLY_DIR
    elseif period == "monthly" then dir = MONTHLY_DIR end

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
    log("Cleaning data older than " .. keep_days .. " days...")
    os.execute("find " .. DAILY_DIR .. " -name '*.json' -mtime +" .. keep_days .. " -delete 2>/dev/null")
    os.execute("find " .. WEEKLY_DIR .. " -name '*.json' -mtime +" .. (keep_days * 4) .. " -delete 2>/dev/null")
    os.execute("find " .. MONTHLY_DIR .. " -name '*.json' -mtime +365 -delete 2>/dev/null")
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
