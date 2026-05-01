--[[
LuCI - Lua Configuration Interface
Model for router-assistant
]]--

local M = {}

-- Lazy require
local uci_cursor = nil

local function get_uci()
    if not uci_cursor then
        local uci = require("luci.model.uci")
        uci_cursor = uci.cursor()
    end
    return uci_cursor
end

-- Configuration section name
local CONFIG_NAME = "router_assistant"

function M.get_config()
    local uci = get_uci()
    if not uci then return {} end
    -- 只读操作：不创建 section，不保存配置
    -- 如果配置不存在，返回空表
    return uci:get_all(CONFIG_NAME) or {}
end

-- 初始化配置（仅在首次设置时调用，不应在 get_config 中调用）
function M.init_config()
    local uci = get_uci()
    if not uci then return end

    -- 检查是否已有配置
    local current = uci:get_all(CONFIG_NAME)
    if current and next(current) then
        return  -- 已存在配置，无需初始化
    end

    -- 创建默认配置
    uci:section(CONFIG_NAME, "global", nil, {
        enabled = "1",
        refresh_interval = "5"
    })
    uci:save(CONFIG_NAME)
end

function M.set_enabled(enabled)
    local uci = get_uci()
    if not uci then return end
    
    uci:set(CONFIG_NAME, "global", "enabled", enabled and "1" or "0")
    uci:save(CONFIG_NAME)
end

function M.get_devices()
    local devices = {}
    local leases = "/tmp/dhcp.leases"

    local fd = io.open(leases, "r")
    if fd then
        for line in fd:lines() do
            local fields = {}
            for w in line:gmatch("%S+") do
                table.insert(fields, w)
            end
            if #fields >= 5 then
                table.insert(devices, {
                    ip = fields[3],
                    mac = fields[2]:upper(),
                    hostname = fields[4],
                    leasetime = fields[1]
                })
            end
        end
        fd:close()
    end

    return devices
end

function M.get_wifi_devices()
    local wifi_devices = {}
    local ok, iwinfo = pcall(require, "iwinfo")
    if not ok then return {} end

    local sys = require("luci.sys")
    for _, dev in ipairs(sys.net.devices()) do
        if dev:match("^wlan") then
            local iface = iwinfo.type(dev)
            if iface then
                local stats = iwinfo.devices(dev)
                table.insert(wifi_devices, {
                    device = dev,
                    type = iface,
                    stats = stats
                })
            end
        end
    end

    return wifi_devices
end

function M.get_traffic_stats()
    local ipset_rx = "traffic_stats_rx"
    local ipset_tx = "traffic_stats_tx"
    local stats = {}

    local f = io.popen("ipset list " .. ipset_rx .. " 2>/dev/null")
    if f then
        for line in f:lines() do
            -- ipset list 输出格式: AA:BB:CC:DD:EE:FF packets:123 bytes:45678
            local mac, packets, bytes = line:match("([%x%x:%-]+)%s+packets:(%d+)%s+bytes:(%d+)")
            if mac and packets and bytes then
                mac = mac:upper()
                stats[mac] = stats[mac] or {}
                stats[mac].rx_packets = tonumber(packets)
                stats[mac].rx_bytes = tonumber(bytes)
            end
        end
        f:close()
    end

    return stats
end

function M.save_config(settings)
    local uci = get_uci()
    if not uci then return end
    
    for k, v in pairs(settings) do
        uci:set(CONFIG_NAME, "global", k, v)
    end
    uci:save(CONFIG_NAME)
end

return M
