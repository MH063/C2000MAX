module("luci.controller.router_assistant", package.seeall)

-- 统一错误响应格式
local function error_response(code, message, details)
    return {
        code = code,
        message = message,
        details = details or "",
        timestamp = os.time()
    }
end

-- 统一成功响应格式
local function success_response(data)
    data = data or {}
    data.code = 0
    data.timestamp = os.time()
    return data
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
end

local function is_wifi_device(client)
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

    local rssi = client.rssi
    if rssi and type(rssi) == "string" and rssi ~= "" and rssi ~= "0" then
        return true
    end
    if rssi and type(rssi) == "number" and rssi ~= 0 then
        return true
    end

    return false
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
                    if validate_mac(mac) and validate_ip(ip) then
                        if name and name ~= "" and name ~= "*" and #name <= 64 then
                            leases[mac] = {ip = ip, name = name}
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
local function load_ipv6_neighbors()
    local neighbors = {}
    local fd = io.popen("ip -6 neigh show 2>/dev/null")
    if fd then
        for line in fd:lines() do
            if line and #line < 512 then
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
local _blocked_macs_cache = nil
local _blocked_macs_cache_time = 0

local function is_device_blocked(mac)
    if not mac or mac == "" then return false end
    local mac_upper = mac:upper()

    -- 缓存黑名单列表，5秒内有效
    local current_time = os.time()
    if _blocked_macs_cache and (current_time - _blocked_macs_cache_time) < 5 then
        return _blocked_macs_cache[mac_upper] == true
    end

    -- 重新加载黑名单
    _blocked_macs_cache = {}
    _blocked_macs_cache_time = current_time

    local util = require("luci.util")

    -- 从iptables输出中提取MAC地址的通用函数
    local function extract_macs_from_iptables(output)
        local macs = {}
        if not output then return macs end

        -- 方法1：匹配 --mac-source XX:XX:XX:XX:XX:XX 格式
        for mac in output:gmatch("--mac%-source%s+([%da-fA-F:]+)") do
            if mac and #mac >= 17 then
                macs[mac:upper()] = true
            end
        end

        -- 方法2：匹配 MACxx:xx:xx:xx:xx:xx 格式（iptables -L 输出格式，MAC前缀无空格）
        for mac in output:gmatch("MAC([%da-fA-F][%da-fA-F:]+)") do
            if mac and #mac >= 17 then
                macs[mac:upper()] = true
            end
        end

        -- 方法3：匹配独立的MAC地址格式 XX:XX:XX:XX:XX:XX（在规则行中）
        for mac in output:gmatch("([%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F])") do
            macs[mac:upper()] = true
        end

        return macs
    end

    -- 检查INPUT链中的DROP规则
    local input_output = util.exec("iptables -L INPUT -n --line-numbers 2>/dev/null")
    if input_output then
        local input_macs = extract_macs_from_iptables(input_output)
        for mac, _ in pairs(input_macs) do
            _blocked_macs_cache[mac] = true
        end
    end

    -- 检查FORWARD链中的DROP规则
    local forward_output = util.exec("iptables -L FORWARD -n --line-numbers 2>/dev/null")
    if forward_output then
        local forward_macs = extract_macs_from_iptables(forward_output)
        for mac, _ in pairs(forward_macs) do
            _blocked_macs_cache[mac] = true
        end
    end

    -- 检查internet_access链
    local access_output = util.exec("iptables -L internet_access -n --line-numbers 2>/dev/null")
    if access_output then
        local access_macs = extract_macs_from_iptables(access_output)
        for mac, _ in pairs(access_macs) do
            _blocked_macs_cache[mac] = true
        end
    end

    return _blocked_macs_cache[mac_upper] == true
end

function api_get_devices()
    local response_data = nil

    local ok, err = pcall(function()
        local util = require("luci.util")

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
            local dhcp_leases = load_dhcp_leases()
            local ipv6_neighbors = load_ipv6_neighbors()
            for mac, client in pairs(data.client) do
                local mac_str = ""
                if mac and type(mac) == "string" then
                    mac_str = mac
                elseif mac then
                    mac_str = tostring(mac)
                end
                local mac_upper = mac_str:upper()

                local is_wifi = is_wifi_device(client)

                local hostname = "Unknown"
                if client.hostname and type(client.hostname) == "string" and client.hostname ~= "" and client.hostname ~= "*" then
                    hostname = client.hostname
                elseif dhcp_leases[mac_upper] then
                    hostname = dhcp_leases[mac_upper].name
                end

                local ip = "-"
                if client.ipaddr and type(client.ipaddr) == "string" then
                    ip = client.ipaddr
                elseif client.ap_ipaddr and type(client.ap_ipaddr) == "string" then
                    ip = client.ap_ipaddr
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

                local is_upstream = (ifname == "eth1" or ifname == "eth3")
                if not is_upstream and not is_device_blocked(mac_upper) then
                    table.insert(devices_list, {
                        ip = ip,
                        ipv6 = ipv6_list,
                        mac = mac_upper,
                        hostname = hostname,
                        device = ifname,
                        is_wifi = is_wifi,
                        signal = rssi,
                        iface = ifname
                    })
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

local _cached_storage_path = nil
local _storage_path_cache_time = 0
local _last_storage_type = nil
local STORAGE_CACHE_TTL = 3600
local DATA_DIR_NAME = "router_assistant"
local DATA_FILE_NAME = "traffic_stats.json"
local NOTES_FILE_NAME = "device_notes.json"
local HISTORY_FILE_NAME = "traffic_history.json"
local ALERTS_FILE_NAME = "traffic_alerts.json"
local BLOCKLIST_FILE_NAME = "mac_blocklist.json"

local function get_storage_type(path)
    if path:find("mmcblk0") or path:find("sdcard") or path:find("storage") then
        return "tf_card"
    end
    return "memory"
end

local function ensure_directory(path)
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

local function save_data_atomic(file_path, data)
    local temp_file = file_path .. ".tmp." .. os.time()
    local fd = io.open(temp_file, "w")
    if not fd then
        return false, "Cannot create temp file"
    end
    
    local ok, err = pcall(function()
        fd:write(data)
        fd:close()
    end)
    
    if not ok then
        os.remove(temp_file)
        return false, err or "Write failed"
    end
    
    local rename_ok = os.rename(temp_file, file_path)
    if not rename_ok then
        os.remove(temp_file)
        return false, "Rename failed"
    end
    
    return true
end

local function save_with_fallback(file_path, data)
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

local function get_data_dir()
    local storage_path = get_storage_path()
    return storage_path:match("^(.+)/[^/]+$") or "/tmp/router_assistant"
end

local function sanitize_input(str)
    if not str or type(str) ~= "string" then return "" end
    str = str:gsub("<", "&lt;")
    str = str:gsub(">", "&gt;")
    str = str:gsub('"', "&quot;")
    str = str:gsub("'", "&#39;")
    str = str:gsub("&", "&amp;")
    str = str:sub(1, 64)
    return str
end

local function load_json_file(filename)
    local dir = get_data_dir()
    local filepath = dir .. "/" .. filename
    local fd = io.open(filepath, "r")
    if not fd then return nil end
    local content = fd:read("*all")
    fd:close()
    if not content or content == "" then return nil end
    local json = require("luci.jsonc")
    local ok, data = pcall(json.parse, content)
    if ok and data then return data end
    return nil
end

local function save_json_file(filename, data)
    local dir = get_data_dir()
    ensure_directory(dir)
    local filepath = dir .. "/" .. filename
    local json = require("luci.jsonc")
    local json_str = json.stringify(data) or "{}"
    return save_data_atomic(filepath, json_str)
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
    return save_data_atomic(filepath, json_str)
end

local function add_to_blocklist(mac, name, ip)
    if not mac or mac == "" then return false end
    local mac_upper = mac:upper()
    local blocklist = load_blocklist()
    for _, device in ipairs(blocklist.devices) do
        if device.mac == mac_upper then
            return true
        end
    end
    table.insert(blocklist.devices, {
        mac = mac_upper,
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
    local new_devices = {}
    for _, device in ipairs(blocklist.devices) do
        if device.mac ~= mac_upper then
            table.insert(new_devices, device)
        end
    end
    blocklist.devices = new_devices
    return save_blocklist(blocklist)
end

local function apply_iptables_block(mac)
    if not mac or mac == "" then return false end
    if not validate_mac(mac) then return false end
    local mac_lower = mac:lower():gsub("[:%-]", "")
    local formatted_mac = mac_lower:sub(1,2) .. ":" .. mac_lower:sub(3,4) .. ":" .. 
                          mac_lower:sub(5,6) .. ":" .. mac_lower:sub(7,8) .. ":" ..
                          mac_lower:sub(9,10) .. ":" .. mac_lower:sub(11,12)
    os.execute("iptables -I INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
    os.execute("iptables -I FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
    return true
end

local function remove_iptables_block(mac)
    if not mac or mac == "" then return false end
    if not validate_mac(mac) then return false end
    local mac_lower = mac:lower():gsub("[:%-]", "")
    local formatted_mac = mac_lower:sub(1,2) .. ":" .. mac_lower:sub(3,4) .. ":" .. 
                          mac_lower:sub(5,6) .. ":" .. mac_lower:sub(7,8) .. ":" ..
                          mac_lower:sub(9,10) .. ":" .. mac_lower:sub(11,12)
    os.execute("iptables -D INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
    os.execute("iptables -D FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
    return true
end

-- ========== MAC屏蔽列表持久化管理结束 ==========

local function aggregate_traffic_history()
    local history = load_json_file(HISTORY_FILE_NAME) or {hourly = {}, daily = {}}
    local current_traffic = load_json_file(DATA_FILE_NAME) or {}
    local current_time = os.time()
    local current_hour = os.date("%Y%m%d%H", current_time)
    local current_day = os.date("%Y%m%d", current_time)

    local total_rx = 0
    local total_tx = 0
    for mac, data in pairs(current_traffic) do
        total_rx = total_rx + (data.rx or 0)
        total_tx = total_tx + (data.tx or 0)
    end

    local last_hour = history.last_hour or ""
    if last_hour ~= current_hour then
        local prev_hourly = history.hourly[history.last_hour] or {}
        local prev_total_rx = prev_hourly.total_rx or 0
        local prev_total_tx = prev_hourly.total_tx or 0

        local delta_rx = total_rx - prev_total_rx
        local delta_tx = total_tx - prev_total_tx
        
        -- 检查是否有有效的历史记录
        local has_valid_history = false
        for _ in pairs(history.hourly or {}) do
            has_valid_history = true
            break
        end
        
        -- 首次采集（无历史记录）时，不记录增量（避免记录累计总量）
        if not has_valid_history then
            delta_rx = 0
            delta_tx = 0
        end
        
        -- 1. 负值处理（计数器重置）
        if delta_rx < 0 then delta_rx = 0 end
        if delta_tx < 0 then delta_tx = 0 end
        
        -- 2. 极小噪声过滤（< 1KB）
        if delta_rx < 1024 then delta_rx = 0 end
        if delta_tx < 1024 then delta_tx = 0 end
        
        -- 不设置任何上限！真实流量无论多高都记录
        
        local function parse_hour(hour_str)
            return os.time({
                year = tonumber(hour_str:sub(1, 4)),
                month = tonumber(hour_str:sub(5, 6)),
                day = tonumber(hour_str:sub(7, 8)),
                hour = tonumber(hour_str:sub(9, 10)) or 0,
                min = 0, sec = 0
            })
        end

        local prev_hour_time = parse_hour(last_hour)
        local curr_hour_time = parse_hour(current_hour)
        local hours_diff = math.floor(os.difftime(curr_hour_time, prev_hour_time) / 3600)

        if hours_diff > 1 and prev_total_rx > 0 then
            local avg_rx = math.floor(delta_rx / hours_diff)
            local avg_tx = math.floor(delta_tx / hours_diff)

            for i = 1, hours_diff - 1 do
                local mid_hour = os.date("%Y%m%d%H", prev_hour_time + i * 3600)
                history.hourly[mid_hour] = {
                    rx = avg_rx,
                    tx = avg_tx,
                    total_rx = prev_total_rx + avg_rx * i,
                    total_tx = prev_total_tx + avg_tx * i,
                    timestamp = prev_hour_time + i * 3600,
                    estimated = true
                }
            end
        end

        history.hourly[current_hour] = {
            rx = delta_rx,
            tx = delta_tx,
            total_rx = total_rx,
            total_tx = total_tx,
            timestamp = current_time
        }
        history.last_hour = current_hour
        local hour_keys = {}
        for k, _ in pairs(history.hourly) do
            table.insert(hour_keys, k)
        end
        table.sort(hour_keys)
        while #hour_keys > 168 do
            local oldest = table.remove(hour_keys, 1)
            history.hourly[oldest] = nil
        end
    end

    local last_day = history.last_day or ""

    local function parse_date(date_str)
        return os.time({
            year = tonumber(date_str:sub(1, 4)),
            month = tonumber(date_str:sub(5, 6)),
            day = tonumber(date_str:sub(7, 8)),
            hour = 0, min = 0, sec = 0
        })
    end

    local function calculate_daily_from_hourly(target_day)
        local day_rx = 0
        local day_tx = 0
        local has_data = false
        -- 异常值过滤：只忽略小于1KB的数据（可能是计数器刚重置的噪声）
        local MIN_THRESHOLD = 1 * 1024  -- 1KB
        for hour_str, hour_data in pairs(history.hourly) do
            if hour_str:sub(1, 8) == target_day then
                local hour_rx = hour_data.rx or 0
                local hour_tx = hour_data.tx or 0
                -- 过滤异常值：只忽略过小的数据（噪声）
                if hour_rx >= MIN_THRESHOLD then
                    day_rx = day_rx + hour_rx
                    has_data = true
                end
                if hour_tx >= MIN_THRESHOLD then
                    day_tx = day_tx + hour_tx
                    has_data = true
                end
            end
        end
        if has_data then
            return day_rx, day_tx
        end
        return nil, nil
    end

    if last_day ~= current_day then
        local prev_daily = history.daily[history.last_day] or {}
        local prev_total_rx = prev_daily.total_rx or 0
        local prev_total_tx = prev_daily.total_tx or 0

        local delta_rx = total_rx - prev_total_rx
        local delta_tx = total_tx - prev_total_tx
        
        -- 检查是否有有效的历史记录
        local has_valid_history = false
        for _ in pairs(history.daily or {}) do
            has_valid_history = true
            break
        end
        
        -- 首次采集（无历史记录）时，不记录增量（避免记录累计总量）
        if not has_valid_history then
            delta_rx = 0
            delta_tx = 0
        end
        
        -- 1. 负值处理（计数器重置）
        if delta_rx < 0 then delta_rx = 0 end
        if delta_tx < 0 then delta_tx = 0 end
        
        -- 2. 极小噪声过滤（< 1KB）
        if delta_rx < 1024 then delta_rx = 0 end
        if delta_tx < 1024 then delta_tx = 0 end
        
        -- 不设置任何上限！真实流量无论多高都记录

        local prev_day_time = parse_date(last_day)
        local curr_day_time = parse_date(current_day)
        local days_diff = math.floor(os.difftime(curr_day_time, prev_day_time) / 86400)

        if days_diff > 1 and prev_total_rx > 0 then
            local avg_rx = math.floor(delta_rx / days_diff)
            local avg_tx = math.floor(delta_tx / days_diff)
            local remaining_rx = delta_rx
            local remaining_tx = delta_tx

            for i = 1, days_diff - 1 do
                local mid_day = os.date("%Y%m%d", prev_day_time + i * 86400)
                local day_rx = avg_rx
                local day_tx = avg_tx
                if i == days_diff - 1 then
                    day_rx = remaining_rx - avg_rx * (days_diff - 2)
                    day_tx = remaining_tx - avg_tx * (days_diff - 2)
                end
                history.daily[mid_day] = {
                    rx = day_rx,
                    tx = day_tx,
                    total_rx = prev_total_rx + avg_rx * i,
                    total_tx = prev_total_tx + avg_tx * i,
                    timestamp = prev_day_time + i * 86400,
                    estimated = true
                }
            end
        end

        history.last_day = current_day
    end

    local day_rx_from_hourly, day_tx_from_hourly = calculate_daily_from_hourly(current_day)

    if day_rx_from_hourly and day_tx_from_hourly then
        history.daily[current_day] = {
            rx = day_rx_from_hourly,
            tx = day_tx_from_hourly,
            total_rx = total_rx,
            total_tx = total_tx,
            timestamp = current_time,
            source = "hourly"
        }
    else
        local existing = history.daily[current_day]
        if not existing or existing.source ~= "hourly" then
            local prev_for_delta = history.daily[history.last_day] or {}
            if last_day == current_day and existing then
                prev_for_delta = {total_rx = existing.snapshot_rx or 0, total_tx = existing.snapshot_tx or 0}
            end
            local prev_total_rx = prev_for_delta.total_rx or 0
            local prev_total_tx = prev_for_delta.total_tx or 0

            local delta_rx = total_rx - prev_total_rx
            local delta_tx = total_tx - prev_total_tx
            if delta_rx < 0 then delta_rx = total_rx end
            if delta_tx < 0 then delta_tx = total_tx end

            history.daily[current_day] = {
                rx = math.max(delta_rx, (existing and existing.rx or 0)),
                tx = math.max(delta_tx, (existing and existing.tx or 0)),
                total_rx = total_rx,
                total_tx = total_tx,
                snapshot_rx = total_rx,
                snapshot_tx = total_tx,
                timestamp = current_time,
                source = "delta"
            }
        else
            history.daily[current_day].total_rx = total_rx
            history.daily[current_day].total_tx = total_tx
            history.daily[current_day].timestamp = current_time
        end
    end

    local day_keys = {}
    for k, _ in pairs(history.daily) do
        table.insert(day_keys, k)
    end
    table.sort(day_keys)
    while #day_keys > 30 do
        local oldest = table.remove(day_keys, 1)
        history.daily[oldest] = nil
    end
    save_json_file(HISTORY_FILE_NAME, history)
    return history
end

function api_get_traffic()
    local response_data = nil

    local ok, err = pcall(function()
        local util = require("luci.util")
        local json = require("luci.jsonc")

        local history_file = get_storage_path()
        local history = {}
        local history_fd = io.open(history_file, "r")
        if history_fd then
            local content = history_fd:read("*all")
            history_fd:close()
            if content and content ~= "" then
                local parse_ok, parsed = pcall(json.parse, content)
                if parse_ok and parsed then
                    history = parsed
                end
            end
        end
        local current_traffic = {}
        local online_devices = {}
        local offline_devices = {}
        local total_rx = 0
        local total_tx = 0
        local online_count = 0
        local offline_count = 0
        local dhcp_leases = load_dhcp_leases()

        local cmd = "ubus call infocd terminal 2>/dev/null"
        local output = util.exec(cmd)
        if output and output ~= "" then
            local parse_ok, data = pcall(json.parse, output)
            if parse_ok and data and data.client then
                for mac, client in pairs(data.client) do
                    local mac_str = (mac and type(mac) == "string") and mac or (mac and tostring(mac)) or ""
                    local mac_upper = mac_str:upper()
                    local real_mac_raw = client.real_mac
                    local real_mac = (real_mac_raw and type(real_mac_raw) == "string" and real_mac_raw ~= "") and real_mac_raw or ""
                    local device_id = (real_mac ~= "" and real_mac ~= mac_str) and real_mac:upper() or mac_upper
                    local hostname = (client.hostname and type(client.hostname) == "string" and client.hostname ~= "" and client.hostname ~= "*") and client.hostname or nil
                    if not hostname then
                        hostname = dhcp_leases[device_id] and dhcp_leases[device_id].name or "Unknown"
                    end
                    local ip = "-"
                    if client.ipaddr and type(client.ipaddr) == "string" and client.ipaddr ~= "" then
                        ip = client.ipaddr
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
                        local mac_prefix = string.sub(device_id, 1, 8):upper()  -- 取MAC前6字节(oui)
                        local matched_devices = {}
                        for hist_mac, hist_data in pairs(history) do
                            local hist_prefix = string.sub(hist_mac, 1, 8):upper()
                            -- 匹配条件：相同hostname + 相同MAC前缀(OUI) + 7天内活跃
                            if hist_data.hostname == hostname and hist_prefix == mac_prefix then
                                local age = current_time - ((hist_data.last_seen) or 0)
                                if age < 604800 then
                                    matched_devices[hist_mac] = hist_data
                                end
                            end
                        end
                        local matched_count = 0
                        for _ in pairs(matched_devices) do matched_count = matched_count + 1 end
                        if matched_count == 1 then
                            -- 只有1台匹配，直接复用
                            for hist_mac, _ in pairs(matched_devices) do
                                device_id = hist_mac
                                break
                            end
                        elseif matched_count > 1 then
                            -- 有2+台匹配，根据IP判断
                            local ip_matched = false
                            for hist_mac, hist_data in pairs(matched_devices) do
                                if hist_data.ip == ip then
                                    device_id = hist_mac
                                    ip_matched = true
                                    break
                                end
                            end
                            -- 如果没有IP匹配的，创建新记录（不复用任何历史）
                        else
                            -- 没有hostname+OUI匹配的，补充判断：hostname + IP相同
                            for hist_mac, hist_data in pairs(history) do
                                if hist_data.hostname == hostname and hist_data.ip == ip then
                                    local age = current_time - ((hist_data.last_seen) or 0)
                                    if age < 604800 then
                                        device_id = hist_mac
                                        break
                                    end
                                end
                            end
                        end
                    end
                    local ifname = (client.ifname and type(client.ifname) == "string") and client.ifname or ""
                    local tx_bytes = 0
                    local rx_bytes = 0
                    if client.txbytes then
                        tx_bytes = (type(client.txbytes) == "number") and client.txbytes or (tonumber(client.txbytes) or 0)
                    end
                    if client.rxbytes then
                        rx_bytes = (type(client.rxbytes) == "number") and client.rxbytes or (tonumber(client.rxbytes) or 0)
                    end
                    if ifname ~= "eth1" and ifname ~= "eth3" then
                        local hist = history[device_id] or {}
                        local last_tx = (hist.tx and type(hist.tx) == "number") and hist.tx or 0
                        local last_rx = (hist.rx and type(hist.rx) == "number") and hist.rx or 0
                        local last_raw_tx = (hist.raw_tx and type(hist.raw_tx) == "number") and hist.raw_tx or 0
                        local last_raw_rx = (hist.raw_rx and type(hist.raw_rx) == "number") and hist.raw_rx or 0
                        local current_time = os.time()
                        local counter_reset = (tx_bytes < last_raw_tx) or (rx_bytes < last_raw_rx)
                        local device_total_tx, device_total_rx
                        if counter_reset then
                            if last_tx > 0 or last_rx > 0 then
                                device_total_tx = tx_bytes + last_tx
                                device_total_rx = rx_bytes + last_rx
                            else
                                device_total_tx = tx_bytes
                                device_total_rx = rx_bytes
                            end
                        else
                            device_total_tx = last_tx + (tx_bytes - last_raw_tx)
                            device_total_rx = last_rx + (rx_bytes - last_raw_rx)
                        end
                        device_total_tx = (device_total_tx and device_total_tx == device_total_tx) and device_total_tx or 0
                        device_total_rx = (device_total_rx and device_total_rx == device_total_rx) and device_total_rx or 0
                        if device_total_tx < 0 then device_total_tx = last_tx end
                        if device_total_rx < 0 then device_total_rx = last_rx end
                        local device_total = device_total_tx + device_total_rx
                        total_rx = total_rx + device_total_rx
                        total_tx = total_tx + device_total_tx
                        online_count = online_count + 1

                        local is_wifi = is_wifi_device(client)

                        table.insert(online_devices, {
                            mac = device_id,
                            hostname = hostname,
                            ip = ip,
                            rx = device_total_rx,
                            tx = device_total_tx,
                            total = device_total,
                            rx_display = format_bytes(device_total_rx),
                            tx_display = format_bytes(device_total_tx),
                            total_display = format_bytes(device_total),
                            online = true,
                            first_seen = hist.first_seen or current_time,
                            is_wifi = is_wifi,
                            ifname = ifname
                        })
                        current_traffic[device_id] = {
                            tx = device_total_tx,
                            rx = device_total_rx,
                            raw_tx = tx_bytes,
                            raw_rx = rx_bytes,
                            ip = ip,
                            hostname = hostname,
                            mac = mac_upper,
                            real_mac = real_mac,
                            last_seen = current_time,
                            first_seen = hist.first_seen or current_time
                        }
                    end
                end
            end
        end
        local current_time = os.time()
        -- 统一历史数据中的MAC地址格式（大写），避免因大小写不一致导致设备被错误归类
        local normalized_history = {}
        for dev_id, data in pairs(history) do
            normalized_history[dev_id:upper()] = data
        end
        history = normalized_history
        for dev_id, data in pairs(history) do
            if not current_traffic[dev_id] then
                local age = current_time - ((data and data.last_seen) or 0)
                if age < 604800 then
                    current_traffic[dev_id] = data
                    local device_total = (data.tx or 0) + (data.rx or 0)
                    offline_count = offline_count + 1
                    total_rx = total_rx + (data.rx or 0)
                    total_tx = total_tx + (data.tx or 0)
                    table.insert(offline_devices, {
                        mac = dev_id,
                        hostname = data.hostname or "Unknown",
                        ip = data.ip or "-",
                        rx = data.rx or 0,
                        tx = data.tx or 0,
                        total = device_total,
                        rx_display = format_bytes(data.rx or 0),
                        tx_display = format_bytes(data.tx or 0),
                        total_display = format_bytes(device_total),
                        online = false,
                        first_seen = data.first_seen or 0,
                        last_seen = data.last_seen or current_time,
                        is_wifi = data.is_wifi or false
                    })
                end
            end
        end
        local json_str = "{}"
        local serialize_ok, serialize_err = pcall(json.stringify, current_traffic)
        if serialize_ok then
            json_str = serialize_err or "{}"
        end
        local save_ok, save_path = save_with_fallback(history_file, json_str)
        aggregate_traffic_history()
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
                total_rx = total_rx,
                total_tx = total_tx,
                online_count = online_count,
                offline_count = offline_count
            }
        }
    end)
    if not ok then
        response_data = error_response(-1, "获取流量统计失败", tostring(err))
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
            local ifname = wifi_info.ifname

            -- 使用iw dev获取真实SSID
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
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")
        local note = luci.http.formvalue("note")
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
        local mac_formatted = mac_clean:sub(1,2) .. ":" .. mac_clean:sub(3,4) .. ":" .. mac_clean:sub(5,6) .. ":" .. mac_clean:sub(7,8) .. ":" .. mac_clean:sub(9,10) .. ":" .. mac_clean:sub(11,12)
        local safe_note = sanitize_input(note or "")
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        notes[mac_formatted] = {
            note = safe_note,
            updated = os.time()
        }
        local save_ok = save_json_file(NOTES_FILE_NAME, notes)
        if not save_ok then
            result = error_response(-1, "保存失败")
            return
        end
        result.message = "备注已保存"
    end)
    if not ok then
        result = error_response(-1, "保存设备备注失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_delete_device_note()
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
        local mac_formatted = mac_clean:sub(1,2) .. ":" .. mac_clean:sub(3,4) .. ":" .. mac_clean:sub(5,6) .. ":" .. mac_clean:sub(7,8) .. ":" .. mac_clean:sub(9,10) .. ":" .. mac_clean:sub(11,12)
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        notes[mac_formatted] = nil
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

function api_collect_traffic()
    local result = {code = 0, message = "流量采集完成"}
    local ok, err = pcall(function()
        aggregate_traffic_history()
    end)
    if not ok then
        result = error_response(-1, "流量采集失败", tostring(err))
    else
        result = success_response(result)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_traffic_history()
    local result = {code = 0, history = {hourly = {}, daily = {}}}
    local ok, err = pcall(function()
        local history = load_json_file(HISTORY_FILE_NAME)
        if history then
            result.history = history
        end
        local period = luci.http.formvalue("period") or "daily"
        if period == "hourly" then
            local hourly_list = {}
            for k, v in pairs(result.history.hourly or {}) do
                table.insert(hourly_list, {time = k, rx = v.rx or 0, tx = v.tx or 0, timestamp = v.timestamp or 0})
            end
            table.sort(hourly_list, function(a, b) return a.time < b.time end)
            result.hourly_list = hourly_list
        else
            local daily_list = {}
            for k, v in pairs(result.history.daily or {}) do
                table.insert(daily_list, {date = k, rx = v.rx or 0, tx = v.tx or 0, timestamp = v.timestamp or 0})
            end
            table.sort(daily_list, function(a, b) return a.date < b.date end)
            result.daily_list = daily_list
        end
    end)
    if not ok then
        result = error_response(-1, "获取流量历史失败", tostring(err))
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
        
        local alerts = {
            global_threshold = threshold_num,
            color_levels = {
                warning = tonumber(warning_level) or 50,
                danger = tonumber(danger_level) or 80,
                critical = tonumber(critical_level) or 100
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

            if ifname and ifname ~= "" then
                -- 优先使用iw dev获取真实SSID（iwinfo可能显示错误的SSID）
                local iw_dev_output = sys.exec("iw dev " .. ifname .. " info 2>/dev/null")
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
                local iwinfo_output = sys.exec("iwinfo " .. ifname .. " info 2>/dev/null")
                
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
                    local iw_output = sys.exec("iw dev " .. ifname .. " link 2>/dev/null")
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
                local stations_output = sys.exec("iwinfo " .. ifname .. " assoclist 2>/dev/null")
                if stations_output and stations_output ~= "" and not stations_output:match("No station") then
                    for mac, signal in stations_output:gmatch("([%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]).-\n%s*Signal:%s*([%-%d]+)%s*dBm") do
                        table.insert(status.connected_stations, {
                            mac = mac,
                            signal = signal .. " dBm"
                        })
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
    local result = {
        version = "1.0.1",
        author = "MH",
        description = "路由助手 - 网络管理工具"
    }

    result = success_response(result)
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_kick_device()
    local http = require "luci.http"
    local util = require "luci.util"
    local os = require "os"

    local response_data = {code = 0, message = "", mac = "", ip = "", success = false}

    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")

        if not mac or mac == "" then
            response_data.code = -1
            response_data.message = "MAC地址无效"
            return
        end

        local mac_colon = mac:upper():gsub("-", ":")
        if not validate_mac(mac_colon) then
            response_data.code = -1
            response_data.message = "MAC地址格式无效"
            return
        end
        local mac_lower = mac_colon:lower()

        local device_ip = ""
        local leases_file = io.open("/tmp/dhcp.leases", "r")
        if leases_file then
            for line in leases_file:lines() do
                local ip = line:match("^%d+%s+%S+%s+" .. mac_lower:gsub(":", "[0-9a-f]") .. "%s+([^%s]+)")
                if not ip then
                    ip = line:match("^%d+%s+" .. mac_lower .. "%s+([^%s]+)")
                end
                if ip then
                    device_ip = ip
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

        if device_ip ~= "" and not validate_ip(device_ip) then
            device_ip = ""
        end

        local kicked = false
        local blocked = false
        local wireless_ifaces = {"ra0", "rai0", "ra1", "rai1", "apcli0", "apcli1"}

        for _, iface in ipairs(wireless_ifaces) do
            local cmd = "iw dev " .. iface .. " station del " .. mac_colon .. " 2>&1"
            local res = util.exec(cmd)
            if res and not res:match("No such") and not res:match("Not found") then
                kicked = true
            end
        end

        local acl_cmd = "access_ctl.sh -m " .. mac_lower .. " -a 0 2>&1"
        local acl_result = util.exec(acl_cmd)
        if acl_result and acl_result ~= "" then
            blocked = true
        end

        if device_ip ~= "" then
            os.execute("conntrack -D -s " .. device_ip .. " 2>/dev/null")
            os.execute("conntrack -D -d " .. device_ip .. " 2>/dev/null")
        end
        os.execute("conntrack -D -m " .. mac_lower .. " 2>/dev/null")

        local formatted_mac = mac_lower:gsub("[:%-]", "")
        formatted_mac = formatted_mac:sub(1,2) .. ":" .. formatted_mac:sub(3,4) .. ":" .. 
                        formatted_mac:sub(5,6) .. ":" .. formatted_mac:sub(7,8) .. ":" ..
                        formatted_mac:sub(9,10) .. ":" .. formatted_mac:sub(11,12)

        os.execute("iptables -I INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
        os.execute("iptables -I FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")

        -- 保存到持久化配置文件
        add_to_blocklist(mac_colon, hostname or "未知设备", device_ip)

        -- 清除黑名单缓存，使更改立即生效
        _blocked_macs_cache = nil
        _blocked_macs_cache_time = 0

        os.execute("ubus call infocdp trigger \"{'sync':1}\" >/dev/null")

        local message = "设备已断开"
        if kicked and blocked then
            message = "设备已强制断开并加入黑名单"
        elseif kicked then
            message = "设备已强制断开"
        elseif blocked then
            message = "设备已加入黑名单"
        end

        response_data.message = message
        response_data.mac = mac_colon
        response_data.ip = device_ip
        response_data.success = true
    end)

    if not ok then
        response_data = error_response(-1, "操作失败: " .. tostring(err))
    else
        response_data = success_response(response_data)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

function api_enable_device()
    local http = require "luci.http"
    local util = require "luci.util"
    local os = require "os"

    local response_data = {code = 0, message = "", mac = "", success = false}

    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")

        if not mac or mac == "" then
            response_data.code = -1
            response_data.message = "MAC地址无效"
            return
        end

        local mac_colon = mac:upper():gsub("-", ":")
        if not validate_mac(mac_colon) then
            response_data.code = -1
            response_data.message = "MAC地址格式无效"
            return
        end
        local mac_lower = mac_colon:lower()

        local formatted_mac = mac_lower:gsub("[:%-]", "")
        formatted_mac = formatted_mac:sub(1,2) .. ":" .. formatted_mac:sub(3,4) .. ":" .. 
                        formatted_mac:sub(5,6) .. ":" .. formatted_mac:sub(7,8) .. ":" ..
                        formatted_mac:sub(9,10) .. ":" .. formatted_mac:sub(11,12)

        os.execute("iptables -D INPUT -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")
        os.execute("iptables -D FORWARD -m mac --mac-source " .. formatted_mac .. " -j DROP 2>/dev/null")

        -- 从持久化配置文件中删除
        remove_from_blocklist(mac_colon)

        -- 清除黑名单缓存，使更改立即生效
        _blocked_macs_cache = nil
        _blocked_macs_cache_time = 0

        -- 通过access_ctl.sh解除限制
        local acl_cmd = "access_ctl.sh -m " .. mac_lower .. " -a 1 2>&1"
        local acl_result = util.exec(acl_cmd)

        -- 同步设备状态
        os.execute("ubus call infocdp trigger \"{'sync':1}\" >/dev/null")

        response_data.message = "设备已解除限制，已恢复网络访问权限"
        response_data.mac = mac_colon
        response_data.success = true
    end)

    if not ok then
        response_data = error_response(-1, "操作失败: " .. tostring(err))
    else
        response_data = success_response(response_data)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

function api_get_blocked_devices()
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

            -- 方法1：匹配 --mac-source XX:XX:XX:XX:XX:XX 格式
            for mac in output:gmatch("--mac%-source%s+([%da-fA-F:]+)") do
                if mac and #mac >= 17 then
                    macs[mac:upper()] = true
                end
            end

            -- 方法2：匹配 MACxx:xx:xx:xx:xx:xx 格式（iptables -L 输出格式，MAC前缀无空格）
            for mac in output:gmatch("MAC([%da-fA-F][%da-fA-F:]+)") do
                if mac and #mac >= 17 then
                    macs[mac:upper()] = true
                end
            end

            -- 方法3：匹配独立的MAC地址格式 XX:XX:XX:XX:XX:XX（在规则行中）
            for mac in output:gmatch("([%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F]:[%da-fA-F][%da-fA-F])") do
                macs[mac:upper()] = true
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
        result = error_response(-1, "获取黑名单设备失败", tostring(err))
    else
        result = success_response(result)
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

function validate_mac(mac)
    if not mac or type(mac) ~= "string" then
        return false
    end
    mac = mac:upper():gsub("[^A-F0-9]", "")
    if #mac ~= 12 then
        return false
    end
    if not mac:match("^[A-F0-9]+$") then
        return false
    end
    if mac == "000000000000" or mac == "FFFFFFFFFFFF" then
        return false
    end
    return true
end

function validate_ip(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end
    if #ip > 15 or #ip < 7 then
        return false
    end
    if ip:match("[^%d%.]") then
        return false
    end
    local parts = {}
    for part in ip:gmatch("[^%.]+") do
        if #part > 1 and part:sub(1,1) == "0" then
            return false
        end
        local num = tonumber(part)
        if not num or num < 0 or num > 255 then
            return false
        end
        table.insert(parts, num)
    end
    if #parts ~= 4 then
        return false
    end
    return true
end

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
                local df_output = util.exec("df -k " .. result.tf_card.mount_point .. " 2>/dev/null | tail -1")
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
                HISTORY_FILE_NAME,
                ALERTS_FILE_NAME
            },
            traffic = {
                DATA_FILE_NAME,
                HISTORY_FILE_NAME
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

local HOMEBOX_BIN = "/usr/bin/homebox"
local HOMEBOX_PORT = 3300
local HOMEBOX_PID_FILE = "/var/run/homebox.pid"

-- 检查 Homebox 是否运行
local function is_homebox_running()
    -- 方法1：检查 PID 文件
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
    local fd = io.popen("ip route show default 2>/dev/null | awk '/src/ {print $NF}' | head -1")
    if fd then
        local ip = fd:read("*l")
        fd:close()
        if ip and ip ~= "" then
            return ip
        end
    end
    -- 备用方案：获取 br-lan IP
    fd = io.popen("ip addr show br-lan 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1")
    if fd then
        local ip = fd:read("*l")
        fd:close()
        if ip and ip ~= "" then
            return ip
        end
    end
    return "192.168.1.1"
end

-- 启动 Homebox 服务
local function start_homebox()
    if is_homebox_running() then
        return true, "Homebox 已在运行"
    end

    -- 检查 Homebox 是否存在
    local fd = io.open(HOMEBOX_BIN, "r")
    if not fd then
        return false, "Homebox 未安装"
    end
    fd:close()

    -- 验证路径安全
    if not safe_path(HOMEBOX_BIN) then
        return false, "Homebox 路径无效"
    end

    -- 确保有执行权限
    os.execute("chmod +x " .. HOMEBOX_BIN .. " 2>/dev/null")
    
    -- 杀掉可能存在的旧进程
    os.execute("killall homebox 2>/dev/null")
    os.remove(HOMEBOX_PID_FILE)

    -- 启动 Homebox（后台运行）
    local start_cmd = HOMEBOX_BIN .. " serve --port " .. tostring(HOMEBOX_PORT) .. 
                      " > /tmp/homebox.log 2>&1 &"
    os.execute(start_cmd)
    
    -- 获取新进程 PID
    local pid_fd = io.popen("pgrep -f 'homebox.*serve' | head -1")
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

    -- 等待服务启动（最多3秒）
    local max_wait = 3
    local waited = 0
    while waited < max_wait do
        if is_homebox_running() then
            return true, "Homebox 启动成功"
        end
        os.execute("sleep 1")
        waited = waited + 1
    end

    -- 检查日志获取错误信息
    local log_fd = io.open("/tmp/homebox.log", "r")
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
        result.url = "http://" .. router_ip .. ":" .. HOMEBOX_PORT
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
            result.url = "http://" .. router_ip .. ":" .. HOMEBOX_PORT
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
