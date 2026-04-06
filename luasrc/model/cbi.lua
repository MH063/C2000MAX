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
    
    uci:section(CONFIG_NAME, "global", nil, {
        enabled = "1",
        refresh_interval = "5"
    })
    uci:save("router_assistant")
    return uci:get_all(CONFIG_NAME)
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
            local mac, packets, bytes = line:match("(%S+) packets:(%d+) bytes:(%d+)")
            if mac and packets and bytes then
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
