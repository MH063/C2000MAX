#!/usr/bin/lua

local fs = require "nixio.fs"
local util = require "luci.util"
local json = require "json"

local TrafficStore = {}
TrafficStore.__index = TrafficStore

local DATA_DIR = "/tmp/traffic_stats"
local DATA_FILE = DATA_DIR .. "/current.json"
local DAILY_DIR = DATA_DIR .. "/daily"
local WEEKLY_DIR = DATA_DIR .. "/weekly"
local MONTHLY_DIR = DATA_DIR .. "/monthly"
local BACKUP_DIR = DATA_DIR .. "/backup"

function TrafficStore.new()
    local self = setmetatable({}, TrafficStore)
    self:init()
    return self
end

function TrafficStore:init()
    fs.mkdir(DATA_DIR)
    fs.mkdir(DAILY_DIR)
    fs.mkdir(WEEKLY_DIR)
    fs.mkdir(MONTHLY_DIR)
    fs.mkdir(BACKUP_DIR)
end

function TrafficStore:getDate()
    return os.date("%Y-%m-%d")
end

function TrafficStore:getWeek()
    local t = os.date("*t")
    local year = t.year
    local week = os.date("%W") or os.date("%j"):sub(1,3)
    return string.format("%d-W%s", year, week)
end

function TrafficStore:getMonth()
    return os.date("%Y-%m")
end

function TrafficStore:saveCurrent(data)
    local f = io.open(DATA_FILE, "w")
    if f then
        f:write(json.encode(data))
        f:close()
        return true
    end
    return false
end

function TrafficStore:loadCurrent()
    local f = io.open(DATA_FILE, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and content ~= "" then
            return json.decode(content)
        end
    end
    return nil
end

function TrafficStore:saveDaily(mac, rx, tx, date)
    date = date or self:getDate()
    local file = DAILY_DIR .. "/" .. date .. ".json"
    local data = self:loadDailySummary(date) or {}

    if not data[mac] then
        data[mac] = {rx = 0, tx = 0, last_update = 0}
    end

    data[mac].rx = (data[mac].rx or 0) + rx
    data[mac].tx = (data[mac].tx or 0) + tx
    data[mac].last_update = os.time()

    local f = io.open(file, "w")
    if f then
        f:write(json.encode(data))
        f:close()
    end

    self:backupFile(file)
    return true
end

function TrafficStore:loadDailySummary(date)
    date = date or self:getDate()
    local file = DAILY_DIR .. "/" .. date .. ".json"
    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        return json.decode(content)
    end
    return nil
end

function TrafficStore:getDailyStats(date)
    local data = self:loadDailySummary(date)
    if not data then return {} end

    local result = {}
    for mac, stats in pairs(data) do
        table.insert(result, {
            mac = mac,
            rx = stats.rx,
            tx = stats.tx,
            total = stats.rx + stats.tx
        })
    end
    table.sort(result, function(a, b) return a.total > b.total end)
    return result
end

function TrafficStore:saveWeekly(mac, rx, tx, week)
    week = week or self:getWeek()
    local file = WEEKLY_DIR .. "/" .. week .. ".json"
    local data = {}

    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and content ~= "" then
            data = json.decode(content) or {}
        end
    end

    if not data[mac] then
        data[mac] = {rx = 0, tx = 0}
    end
    data[mac].rx = (data[mac].rx or 0) + rx
    data[mac].tx = (data[mac].tx or 0) + tx

    f = io.open(file, "w")
    if f then
        f:write(json.encode(data))
        f:close()
    end

    self:backupFile(file)
    return true
end

function TrafficStore:getWeeklyStats(week)
    week = week or self:getWeek()
    local file = WEEKLY_DIR .. "/" .. week .. ".json"
    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        local data = json.decode(content)
        if data then
            local result = {}
            for mac, stats in pairs(data) do
                table.insert(result, {
                    mac = mac,
                    rx = stats.rx,
                    tx = stats.tx,
                    total = stats.rx + stats.tx
                })
            end
            table.sort(result, function(a, b) return a.total > b.total end)
            return result
        end
    end
    return {}
end

function TrafficStore:saveMonthly(mac, rx, tx, month)
    month = month or self:getMonth()
    local file = MONTHLY_DIR .. "/" .. month .. ".json"
    local data = {}

    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and content ~= "" then
            data = json.decode(content) or {}
        end
    end

    if not data[mac] then
        data[mac] = {rx = 0, tx = 0}
    end
    data[mac].rx = (data[mac].rx or 0) + rx
    data[mac].tx = (data[mac].tx or 0) + tx

    f = io.open(file, "w")
    if f then
        f:write(json.encode(data))
        f:close()
    end

    self:backupFile(file)
    return true
end

function TrafficStore:getMonthlyStats(month)
    month = month or self:getMonth()
    local file = MONTHLY_DIR .. "/" .. month .. ".json"
    local f = io.open(file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        local data = json.decode(content)
        if data then
            local result = {}
            for mac, stats in pairs(data) do
                table.insert(result, {
                    mac = mac,
                    rx = stats.rx,
                    tx = stats.tx,
                    total = stats.rx + stats.tx
                })
            end
            table.sort(result, function(a, b) return a.total > b.total end)
            return result
        end
    end
    return {}
end

function TrafficStore:backupFile(file)
    local name = file:match("([^/]+)$")
    local backup_file = BACKUP_DIR .. "/" .. name .. ".bak"
    local f1 = io.open(file, "r")
    if f1 then
        local content = f1:read("*all")
        f1:close()
        local f2 = io.open(backup_file, "w")
        if f2 then
            f2:write(content)
            f2:close()
        end
    end
end

function TrafficStore:getHistoryList(period, limit)
    local dir = DAILY_DIR
    if period == "weekly" then dir = WEEKLY_DIR
    elseif period == "monthly" then dir = MONTHLY_DIR end

    local files = {}
    for f in util.execi("ls -t " .. dir .. "/*.json 2>/dev/null | head -" .. (limit or 30)) do
        local name = f:match("([^/]+)%.json")
        if name then
            table.insert(files, {period = period, key = name, file = dir .. "/" .. f})
        end
    end
    return files
end

function TrafficStore:cleanOld(period, keep_days)
    local dir = DAILY_DIR
    if period == "weekly" then dir = WEEKLY_DIR
    elseif period == "monthly" then dir = MONTHLY_DIR end

    keep_days = keep_days or 90
    util.exec("find " .. dir .. " -name '*.json' -mtime +" .. keep_days .. " -delete 2>/dev/null")
end

function TrafficStore:restoreFromBackup(period, key)
    local dir = DAILY_DIR
    if period == "weekly" then dir = WEEKLY_DIR
    elseif period == "monthly" then dir = MONTHLY_DIR end

    local backup_file = BACKUP_DIR .. "/" .. key .. ".json.bak"
    local target_file = dir .. "/" .. key .. ".json"

    local f1 = io.open(backup_file, "r")
    if f1 then
        local content = f1:read("*all")
        f1:close()
        local f2 = io.open(target_file, "w")
        if f2 then
            f2:write(content)
            f2:close()
            return true
        end
    end
    return false
end

function TrafficStore:getPeriodList()
    local result = {}

    local daily = {}
    for f in util.execi("ls -t " .. DAILY_DIR .. "/*.json 2>/dev/null | head -30") do
        local name = f:match("([^/]+)%.json")
        if name then table.insert(daily, name) end
    end
    result.daily = daily

    local weekly = {}
    for f in util.execi("ls -t " .. WEEKLY_DIR .. "/*.json 2>/dev/null | head -12") do
        local name = f:match("([^/]+)%.json")
        if name then table.insert(weekly, name) end
    end
    result.weekly = weekly

    local monthly = {}
    for f in util.execi("ls -t " .. MONTHLY_DIR .. "/*.json 2>/dev/null | head -12") do
        local name = f:match("([^/]+)%.json")
        if name then table.insert(monthly, name) end
    end
    result.monthly = monthly

    return result
end

return TrafficStore
