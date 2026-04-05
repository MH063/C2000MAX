module("luci.controller.router_assistant", package.seeall)

function index()
    entry({"admin", "status", "router_assistant"}, template("router_assistant/panel"), "路由助手", 50).dependent = true
    entry({"admin", "status", "router_assistant", "get_devices"}, call("api_get_devices")).leaf = true
    entry({"admin", "status", "router_assistant", "get_traffic"}, call("api_get_traffic")).leaf = true
    entry({"admin", "status", "router_assistant", "get_wifi"}, call("api_get_wifi")).leaf = true
    entry({"admin", "status", "router_assistant", "get_wifi_status"}, call("api_get_wifi_status")).leaf = true
    entry({"admin", "status", "router_assistant", "get_version"}, call("api_get_version")).leaf = true
    entry({"admin", "status", "router_assistant", "kick_device"}, post("api_kick_device")).leaf = true
    entry({"admin", "status", "router_assistant", "enable_device"}, post("api_enable_device")).leaf = true
    entry({"admin", "status", "router_assistant", "get_blocked"}, call("api_get_blocked_devices")).leaf = true
    entry({"admin", "status", "router_assistant", "get_storage_status"}, call("api_get_storage_status")).leaf = true
    entry({"admin", "status", "router_assistant", "migrate_storage"}, post("api_migrate_storage")).leaf = true
    entry({"admin", "status", "router_assistant", "clear_data"}, post("api_clear_data")).leaf = true
    entry({"admin", "status", "router_assistant", "get_device_notes"}, call("api_get_device_notes")).leaf = true
    entry({"admin", "status", "router_assistant", "save_device_note"}, post("api_save_device_note")).leaf = true
    entry({"admin", "status", "router_assistant", "delete_device_note"}, post("api_delete_device_note")).leaf = true
    entry({"admin", "status", "router_assistant", "get_traffic_history"}, call("api_get_traffic_history")).leaf = true
    entry({"admin", "status", "router_assistant", "get_alerts"}, call("api_get_alerts")).leaf = true
    entry({"admin", "status", "router_assistant", "save_alert"}, post("api_save_alert")).leaf = true
    entry({"admin", "status", "router_assistant", "delete_alert"}, post("api_delete_alert")).leaf = true
end

local function get_csrf_token()
    local sys = require("luci.sys")
    return sys.uniqueid(16)
end

local function validate_csrf()
    local http = require("luci.http")
    local token = http.formvalue("token") or http.getenv("HTTP_X_CSRF_TOKEN")
    local session_token = require("luci.dispatcher").context.csrf_token
    
    if not token or not session_token or token ~= session_token then
        return false
    end
    return true
end

function is_wifi_device(client)
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

function api_get_devices()
    local response_data = nil

    local ok, err = pcall(function()
        local util = require("luci.util")

        local cmd = "ubus call infocd terminal 2>/dev/null"
        local output = util.exec(cmd)

        local devices_list = {}

        if output and output ~= "" then
            local json = require("luci.jsonc")
            local parse_ok, data = pcall(json.parse, output)
            if parse_ok and data and data.client then
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
                    if client.hostname and type(client.hostname) == "string" then
                        hostname = client.hostname
                    end

                    local ip = "-"
                    if client.ipaddr and type(client.ipaddr) == "string" then
                        ip = client.ipaddr
                    elseif client.ap_ipaddr and type(client.ap_ipaddr) == "string" then
                        ip = client.ap_ipaddr
                    end

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
                    if not is_upstream then
                        table.insert(devices_list, {
                            ip = ip,
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
        end

        response_data = {code = 0, devices = devices_list}
    end)

    if not ok then
        os.execute("echo 'api_get_devices error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
        response_data = {code = -1, message = "Internal error: " .. tostring(err), devices = {}}
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

local function get_storage_type(path)
    if path:find("mmcblk0") or path:find("sdcard") or path:find("storage") then
        return "tf_card"
    end
    return "memory"
end

local function ensure_directory(path)
    local dir = path:match("^(.+)/[^/]+$")
    if dir and dir ~= "" then
        local check_fd = io.open(dir, "r")
        if not check_fd then
            os.execute("mkdir -p " .. dir .. " 2>/dev/null")
        else
            check_fd:close()
        end
    end
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
                    local hostname = (client.hostname and type(client.hostname) == "string" and client.hostname ~= "") and client.hostname or "Unknown"
                    local ip = "-"
                    if client.ipaddr and type(client.ipaddr) == "string" and client.ipaddr ~= "" then
                        ip = client.ipaddr
                    elseif client.ap_ipaddr and type(client.ap_ipaddr) == "string" and client.ap_ipaddr ~= "" then
                        ip = client.ap_ipaddr
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
                            first_seen = hist.first_seen or current_time
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
        response_data = {code = -1, message = "Error: " .. tostring(err), online_devices = {}, offline_devices = {}, stats = {}}
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

function api_get_wifi()
    local result = {code = 0, wifi = {}}

    local ok, err = pcall(function()
        local iwinfo = require("iwinfo")

        local devices = iwinfo.devices() or {}

        for _, dev in ipairs(devices) do
            local info = iwinfo.type(dev)
            if info then
                local iface = iwinfo[info]
                if iface then
                    local ssid = iface.ssid(dev) or "-"
                    if ssid ~= "" and ssid ~= "-" then
                        table.insert(result.wifi, {
                            iface = dev,
                            ssid = ssid,
                            mode = iface.mode(dev) or "-",
                            channel = iface.channel(dev) or "-",
                            signal = iface.signal(dev) or "-",
                            encryption = get_encryption(iface, dev)
                        })
                    end
                end
            end
        end
    end)

    if not ok then
        os.execute("echo 'api_get_wifi error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
    end

    if #result.wifi == 0 then
        local uci = require("luci.model.uci").cursor()
        uci:foreach("wireless", "wifi-iface", function(s)
            table.insert(result.wifi, {
                iface = s[".name"] or "-",
                ssid = s.ssid or "-",
                mode = s.mode or "ap",
                channel = "-",
                signal = "-",
                encryption = s.encryption or "none"
            })
        end)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
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

function api_get_device_notes()
    local result = {code = 0, notes = {}}
    local ok, err = pcall(function()
        local notes = load_json_file(NOTES_FILE_NAME)
        if notes then
            result.notes = notes
        end
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
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
        if not validate_mac(mac) then
            result.code = -1
            result.message = "MAC地址格式无效"
            return
        end
        local mac_upper = mac:upper():gsub("-", ":")
        local safe_note = sanitize_input(note or "")
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        notes[mac_upper] = {
            note = safe_note,
            updated = os.time()
        }
        local save_ok = save_json_file(NOTES_FILE_NAME, notes)
        if not save_ok then
            result.code = -1
            result.message = "保存失败"
            return
        end
        result.message = "备注已保存"
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
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
        local mac_upper = mac:upper():gsub("-", ":")
        local notes = load_json_file(NOTES_FILE_NAME) or {}
        notes[mac_upper] = nil
        save_json_file(NOTES_FILE_NAME, notes)
        result.message = "备注已删除"
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

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
        history.hourly[current_hour] = {
            rx = total_rx,
            tx = total_tx,
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
    if last_day ~= current_day then
        history.daily[current_day] = {
            rx = total_rx,
            tx = total_tx,
            timestamp = current_time
        }
        history.last_day = current_day
        local day_keys = {}
        for k, _ in pairs(history.daily) do
            table.insert(day_keys, k)
        end
        table.sort(day_keys)
        while #day_keys > 30 do
            local oldest = table.remove(day_keys, 1)
            history.daily[oldest] = nil
        end
    end
    save_json_file(HISTORY_FILE_NAME, history)
    return history
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
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_alerts()
    local result = {code = 0, alerts = {}, triggered = {}}
    local ok, err = pcall(function()
        local alerts = load_json_file(ALERTS_FILE_NAME)
        if alerts then
            result.alerts = alerts
        end
        local current_traffic = load_json_file(DATA_FILE_NAME) or {}
        for mac, alert in pairs(result.alerts) do
            local traffic = current_traffic[mac]
            if traffic then
                local total = (traffic.rx or 0) + (traffic.tx or 0)
                local threshold = alert.threshold or 0
                if threshold > 0 and total >= threshold then
                    table.insert(result.triggered, {
                        mac = mac,
                        hostname = traffic.hostname or "Unknown",
                        total = total,
                        threshold = threshold,
                        percent = threshold > 0 and math.floor(total / threshold * 100) or 0
                    })
                end
            end
        end
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_save_alert()
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")
        local threshold = luci.http.formvalue("threshold")
        if not mac or mac == "" then
            result.code = -1
            result.message = "MAC地址无效"
            return
        end
        local mac_upper = mac:upper():gsub("-", ":")
        local threshold_num = tonumber(threshold) or 0
        if threshold_num <= 0 then
            result.code = -1
            result.message = "阈值必须大于0"
            return
        end
        local alerts = load_json_file(ALERTS_FILE_NAME) or {}
        alerts[mac_upper] = {
            threshold = threshold_num,
            created = os.time()
        }
        local save_ok = save_json_file(ALERTS_FILE_NAME, alerts)
        if not save_ok then
            result.code = -1
            result.message = "保存失败"
            return
        end
        result.message = "报警设置已保存"
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_delete_alert()
    local result = {code = 0, message = ""}
    local ok, err = pcall(function()
        local mac = luci.http.formvalue("mac")
        if not mac or mac == "" then
            result.code = -1
            result.message = "MAC地址无效"
            return
        end
        local mac_upper = mac:upper():gsub("-", ":")
        local alerts = load_json_file(ALERTS_FILE_NAME) or {}
        alerts[mac_upper] = nil
        save_json_file(ALERTS_FILE_NAME, alerts)
        result.message = "报警已删除"
    end)
    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_wifi_status()
    local result = {code = 0, wifi_status = {}}

    local ok, err = pcall(function()
        local uci = require("luci.model.uci").cursor()
        local iwinfo = require("iwinfo")

        uci:foreach("wireless", "wifi-iface", function(s)
            local device = s.device or "radio0"
            local iface = s[".name"]
            local network = s.network

            local status = {
                iface = iface,
                device = device,
                ssid = s.ssid or "-",
                encryption = s.encryption or "none",
                mode = s.mode or "ap",
                channel = "-",
                signal = "-",
                status = "unknown",
                ip = "-",
                tx_bitrate = "-",
                rx_bitrate = "-",
                frequency = "-",
                connected_stations = {}
            }

            local info = iwinfo.type(device)
            if info then
                local iface_api = iwinfo[info]
                if iface_api then
                    status.channel = iface_api.channel(device) or "-"
                    status.signal = iface_api.signal(device) or "-"
                    status.frequency = iface_api.frequency(device) or "-"

                    local tx, rx = iface_api.bitrate(device)
                    if tx then status.tx_bitrate = tostring(tx) .. " Mbps" end
                    if rx then status.rx_bitrate = tostring(rx) .. " Mbps" end

                    local stations = iface_api.assoclist(device)
                    if stations then
                        for mac, data in pairs(stations) do
                            table.insert(status.connected_stations, {
                                mac = mac,
                                signal = data.signal or "-",
                                rx_rate = data.rx_rate or "-",
                                tx_rate = data.tx_rate or "-"
                            })
                        end
                    end
                end
            end

            if network then
                local net = require("luci.model.network").get_network(network)
                if net then
                    local addr = net:ipaddr()
                    if addr then status.ip = addr end
                end
            end

            status.status = "connected"
            table.insert(result.wifi_status, status)
        end)
    end)

    if not ok then
        os.execute("echo 'api_get_wifi_status error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

function api_get_version()
    local result = {
        code = 0,
        version = "1.0.1",
        author = "MH",
        description = "路由助手 - 网络管理工具"
    }

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

        os.execute("iptables -I INPUT -m mac --mac-source " .. mac_lower .. " -j DROP 2>/dev/null")
        os.execute("iptables -I FORWARD -m mac --mac-source " .. mac_lower .. " -j DROP 2>/dev/null")

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
        response_data.code = -1
        response_data.message = "操作失败: " .. tostring(err)
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

        local acl_cmd = "access_ctl.sh -m " .. mac_lower .. " -a 1 2>&1"
        local acl_result = util.exec(acl_cmd)

        os.execute("ubus call infocdp trigger \"{'sync':1}\" >/dev/null")

        response_data.message = "设备已解除限制"
        response_data.mac = mac_colon
        response_data.success = true
    end)

    if not ok then
        os.execute("echo 'api_enable_device error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
        response_data.code = -1
        response_data.message = "操作失败: " .. tostring(err)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

function api_get_blocked_devices()
    local util = require "luci.util"
    local result = {code = 0, blocked = {}}

    local ok, err = pcall(function()
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

        local iptables_output = util.exec("iptables -L internet_access -n --line-numbers 2>/dev/null")
        if iptables_output then
            local blocked_macs = {}
            for line in iptables_output:gmatch("[^\n]+") do
                local mac = line:match("MAC([%x:]+)")
                if mac then
                    local mac_upper = mac:upper()
                    if not blocked_macs[mac_upper] then
                        blocked_macs[mac_upper] = true
                        local info = device_info[mac_upper] or {}
                        table.insert(result.blocked, {
                            mac = mac_upper,
                            name = info.name or "未知设备",
                            ip = info.ip or "",
                            switch = 0
                        })
                    end
                end
            end
        end
    end)

    if not ok then
        os.execute("echo 'api_get_blocked_devices error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
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
    local pattern = "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
    return mac:match(pattern) ~= nil
end

function validate_ip(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end
    local pattern = "^([01]?%d%d?|[2][0-4]%d|[25][0-5])%.([01]?%d%d?|[2][0-4]%d|[25][0-5])%.([01]?%d%d?|[2][0-4]%d|[25][0-5])%.([01]?%d%d?|[2][0-4]%d|[25][0-5])$"
    return ip:match(pattern) ~= nil
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
        result.code = -1
        result.message = "Error: " .. tostring(err)
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
            result.code = -1
            result.message = "迁移失败: " .. tostring(save_err)
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
        result.code = -1
        result.message = "Error: " .. tostring(err)
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
        
        local fd = io.open(storage_path, "r")
        if not fd then
            result.code = 1
            result.message = "数据文件不存在"
            return
        end
        fd:close()
        
        os.remove(storage_path)
        result.deleted_path = storage_path
        result.message = "数据已清除"
        
        _cached_storage_path = nil
    end)

    if not ok then
        result.code = -1
        result.message = "Error: " .. tostring(err)
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
