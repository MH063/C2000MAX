module("luci.controller.router_assistant", package.seeall)

function index()
    entry({"admin", "services", "router_assistant"}, alias("admin", "services", "router_assistant", "panel"), _("RouterAssistant"), 50, true).index = true
    entry({"admin", "services", "router_assistant", "panel"}, template("router_assistant/panel"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_devices"}, call("api_get_devices"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_traffic"}, call("api_get_traffic"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_wifi"}, call("api_get_wifi"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_wifi_status"}, call("api_get_wifi_status"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_version"}, call("api_get_version"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "kick_device"}, post("api_kick_device"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "enable_device"}, post("api_enable_device"), nil, nil, true).leaf = true
    entry({"admin", "services", "router_assistant", "get_blocked"}, call("api_get_blocked_devices"), nil, nil, true).leaf = true
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

                    local is_wifi = (client.type == "wireless")

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

                    local is_upstream = (ifname == "eth1" or ifname == "eth2" or ifname == "eth3")
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

function api_get_traffic()
    os.execute("echo '=== api_get_traffic start ===' > /tmp/traffic_debug.log")

    local response_data = nil

    local ok, err = pcall(function()
        local util = require("luci.util")

        local history_dir = nil
        local history_file = nil

        local tf_cache_file = "/tmp/.tf_card_cache"
        local cache_fd = io.open(tf_cache_file, "r")
        if cache_fd then
            local cached_base = cache_fd:read("*line")
            cache_fd:close()
            if cached_base and cached_base ~= "" and cached_base ~= "/tmp/traffic_history_tmp" then
                local test_fd = io.open(cached_base .. "/.write_test", "w")
                if test_fd then
                    test_fd:close()
                    os.execute("rm -f " .. cached_base .. "/.write_test 2>/dev/null")
                    history_dir = cached_base .. "/traffic_history"
                    history_file = history_dir .. "/devices.json"
                    os.execute("echo 'Using cached TF path: " .. history_dir .. "' >> /tmp/traffic_debug.log")
                else
                    os.execute("echo 'Cached TF path not writable, rechecking: " .. cached_base .. "' >> /tmp/traffic_debug.log")
                    os.execute("rm -f " .. tf_cache_file .. " 2>/dev/null")
                    cached_base = nil
                end
            else
                if cached_base then
                    os.execute("echo 'Cached memory path, skipping cache: " .. cached_base .. "' >> /tmp/traffic_debug.log")
                end
                os.execute("rm -f " .. tf_cache_file .. " 2>/dev/null")
                cached_base = nil
            end
        end

        if not history_dir then
            local tf_dev = "/dev/mmcblk0"
            local dev_check = io.open(tf_dev, "r")
            if dev_check then
                dev_check:close()
                local mount_output = util.exec("cat /proc/mounts | grep mmcblk0")
                if mount_output and mount_output ~= "" then
                    local mount_path = mount_output:match("/([%w_]+/mmcblk0p1)%s+f2fs")
                    if mount_path then
                        mount_path = "/" .. mount_path
                    else
                        mount_path = mount_output:match("(/tmp/storage/mmcblk0p1)")
                    end
                    if not mount_path then
                        mount_path = mount_output:match("(/mnt/mmcblk0p1)")
                    end
                    if not mount_path then
                        mount_path = mount_output:match("(/tmp/mnt/mmcblk0p1)")
                    end

                    if mount_path then
                        local test_fd = io.open(mount_path .. "/.write_test", "w")
                        if test_fd then
                            test_fd:close()
                            os.execute("rm -f " .. mount_path .. "/.write_test 2>/dev/null")
                            history_dir = mount_path .. "/traffic_history"
                            history_file = history_dir .. "/devices.json"
                            os.execute("echo 'New TF path detected: " .. history_dir .. "' >> /tmp/traffic_debug.log")
                            local cache_out = io.open(tf_cache_file, "w")
                            if cache_out then
                                cache_out:write(mount_path)
                                cache_out:close()
                                os.execute("echo 'TF cache updated: " .. mount_path .. "' >> /tmp/traffic_debug.log")
                            else
                                os.execute("echo 'Failed to update TF cache' >> /tmp/traffic_debug.log")
                            end
                        else
                            os.execute("echo 'TF path not writable: " .. mount_path .. "' >> /tmp/traffic_debug.log")
                        end
                    else
                        os.execute("echo 'TF card mounted but path not matched' >> /tmp/traffic_debug.log")
                    end
                else
                    os.execute("echo 'TF card device exists but not mounted' >> /tmp/traffic_debug.log")
                end
            else
                os.execute("echo 'TF card not detected' >> /tmp/traffic_debug.log")
            end
        end

        if not history_dir then
            history_dir = "/tmp/traffic_history_tmp"
            history_file = history_dir .. "/devices.json"
            os.execute("echo 'Using temp memory storage' >> /tmp/traffic_debug.log")
        end

        os.execute("mkdir -p " .. history_dir .. " 2>/dev/null")

        local history = {}
        local history_fd = io.open(history_file, "r")
        if history_fd then
            local content = history_fd:read("*a")
            history_fd:close()
            if content and content ~= "" then
                local json = require("luci.jsonc")
                local parse_ok, data = pcall(json.parse, content)
                if parse_ok and type(data) == "table" then
                    history = data
                    local hist_count = 0
                    for _ in pairs(history) do hist_count = hist_count + 1 end
                    os.execute("echo 'Loaded history: " .. tostring(hist_count) .. " devices' >> /tmp/traffic_debug.log")
                end
            end
        else
            os.execute("echo 'No history file, starting fresh' >> /tmp/traffic_debug.log")
        end

        local cmd = "ubus call infocd terminal 2>/dev/null"
        local output = util.exec(cmd)

        os.execute("echo 'ubus output length: " .. tostring(#output) .. "' >> /tmp/traffic_debug.log")

        local devices_list = {}
        local current_traffic = {}
        local device_count = 0

        if output and output ~= "" then
            local json = require("luci.jsonc")
            local parse_ok, data = pcall(json.parse, output)
            if parse_ok and data and data.client then
                for mac, client in pairs(data.client) do
                    device_count = device_count + 1

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

                    if ifname ~= "eth1" and ifname ~= "eth2" and ifname ~= "eth3" then
                        local hist = history[device_id] or {}
                        local last_tx = (hist.tx and type(hist.tx) == "number") and hist.tx or 0
                        local last_rx = (hist.rx and type(hist.rx) == "number") and hist.rx or 0
                        local last_raw_tx = (hist.raw_tx and type(hist.raw_tx) == "number") and hist.raw_tx or 0
                        local last_raw_rx = (hist.raw_rx and type(hist.raw_rx) == "number") and hist.raw_rx or 0

                        local current_time = os.time()
                        local counter_reset = (tx_bytes < last_raw_tx) or (rx_bytes < last_raw_rx)

                        local total_tx, total_rx
                        if counter_reset then
                            if last_tx > 0 or last_rx > 0 then
                                total_tx = tx_bytes + last_tx
                                total_rx = rx_bytes + last_rx
                                os.execute("echo 'Counter reset for " .. device_id .. ": adding history' >> /tmp/traffic_debug.log")
                            else
                                total_tx = tx_bytes
                                total_rx = rx_bytes
                            end
                        else
                            total_tx = last_tx + (tx_bytes - last_raw_tx)
                            total_rx = last_rx + (rx_bytes - last_raw_rx)
                        end

                        total_tx = (total_tx and total_tx == total_tx) and total_tx or 0
                        total_rx = (total_rx and total_rx == total_rx) and total_rx or 0
                        if total_tx < 0 then total_tx = last_tx end
                        if total_rx < 0 then total_rx = last_rx end

                        local total = total_tx + total_rx

                        table.insert(devices_list, {
                            mac = device_id,
                            hostname = hostname,
                            ip = ip,
                            rx = total_rx,
                            tx = total_tx,
                            total = total,
                            rx_display = format_bytes(total_rx),
                            tx_display = format_bytes(total_tx),
                            total_display = format_bytes(total)
                        })

                        current_traffic[device_id] = {
                            tx = total_tx,
                            rx = total_rx,
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

        os.execute("echo 'Current devices: " .. device_count .. "' >> /tmp/traffic_debug.log")

        local current_time = os.time()
        for dev_id, data in pairs(history) do
            if not current_traffic[dev_id] then
                local age = current_time - ((data and data.last_seen) or 0)
                if age < 604800 then
                    current_traffic[dev_id] = data
                end
            end
        end

        local json = require("luci.jsonc")
        local json_str = "{}"
        local serialize_ok, serialize_err = pcall(json.stringify, current_traffic)
        if serialize_ok then
            json_str = serialize_err or "{}"
        end

        local save_fd = io.open(history_file, "w")
        if save_fd then
            save_fd:write(json_str)
            save_fd:close()
            local save_count = 0
            for _ in pairs(current_traffic) do save_count = save_count + 1 end
            os.execute("echo 'Saved " .. tostring(save_count) .. " devices to TF card' >> /tmp/traffic_debug.log")
        else
            os.execute("echo 'ERROR: Failed to save to TF card' >> /tmp/traffic_debug.log")
        end

        table.sort(devices_list, function(a, b)
            local ta = (a and a.total) or 0
            local tb = (b and b.total) or 0
            return ta > tb
        end)

        response_data = {code = 0, devices = devices_list}
    end)

    if not ok then
        os.execute("echo 'api_get_traffic error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
        response_data = {code = -1, message = "Error: " .. tostring(err), devices = {}}
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

        local message = "设备已踢出"
        if kicked and blocked then
            message = "设备已强制断开并加入黑名单"
        elseif kicked then
            message = "设备已强制断开（黑名单可能失败）"
        elseif blocked then
            message = "设备已加入黑名单"
        end

        response_data.message = message
        response_data.mac = mac_colon
        response_data.ip = device_ip
        response_data.success = true
    end)

    if not ok then
        os.execute("echo 'api_kick_device error: " .. tostring(err) .. "' >> /tmp/traffic_debug.log")
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

        response_data.message = "设备已解禁"
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
    -- 安全处理：确保 bytes 是有效数字
    if not bytes or type(bytes) ~= "number" or bytes ~= bytes then -- bytes ~= bytes 是 NaN 检查
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
