# 路由管家插件重构实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将8600行单文件重构为模块化结构，统一MAC格式，完善CSRF保护，优化Shell调用

**Architecture:** 渐进式重构 - 先创建新模块，与旧代码并行运行，验证后逐步切换

**Tech Stack:** Lua, LuCI框架, ubus API, JSON存储

---

## 阶段0：创建基础模块

### Task 0.1: 创建 utils 目录结构

**Files:**
- Create: `luasrc/utils/`

**Step 1: 创建目录**

```bash
mkdir -p luasrc/utils
```

**Step 2: 创建 .gitkeep 文件**

```bash
touch luasrc/utils/.gitkeep
```

**Step 3: 验证目录创建成功**

```bash
ls -la luasrc/utils/
```
Expected: 显示 .gitkeep 文件

---

### Task 0.2: 创建 utils/validate.lua

**Files:**
- Create: `luasrc/utils/validate.lua`

**Step 1: 创建验证模块**

```lua
--[[
    验证工具模块
    提供MAC地址、IP地址、CSRF等验证功能
]]--
local M = {}

-- 统一MAC格式化为带冒号大写格式
-- @param mac string 任意格式的MAC地址
-- @return string|nil 格式化后的MAC（AA:BB:CC:DD:EE:FF）或nil
function M.format_mac(mac)
    if not mac or type(mac) ~= "string" then
        return nil
    end
    local clean = mac:upper():gsub("[^A-F0-9]", "")
    if #clean ~= 12 then
        return nil
    end
    if clean == "000000000000" or clean == "FFFFFFFFFFFF" then
        return nil
    end
    return string.format("%s:%s:%s:%s:%s:%s",
        clean:sub(1,2), clean:sub(3,4), clean:sub(5,6),
        clean:sub(7,8), clean:sub(9,10), clean:sub(11,12))
end

-- 验证MAC地址并返回格式化结果
-- @param mac string 原始MAC地址
-- @return string|nil 格式化后的MAC或nil
function M.validate_mac(mac)
    return M.format_mac(mac)
end

-- 验证IP地址（IPv4）
-- @param ip string 原始IP地址
-- @return string|nil 验证通过的IP地址或nil
function M.validate_ip(ip)
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

-- 验证CSRF Token
-- @return boolean 是否验证通过
function M.validate_csrf()
    local http = require("luci.http")
    local dispatcher = require("luci.dispatcher")
    
    local token = http.formvalue("token")
    if not token or token == "" then
        return false
    end
    
    local session_token = dispatcher.context.token
    if not session_token or session_token == "" then
        return true
    end
    
    return token == session_token
end

-- 要求CSRF验证（失败时返回错误响应）
-- @return boolean 是否验证通过
function M.require_csrf()
    if not M.validate_csrf() then
        local http = require("luci.http")
        http.prepare_content("application/json")
        http.write_json({
            code = -403,
            message = "CSRF验证失败，请刷新页面重试",
            timestamp = os.time()
        })
        return false
    end
    return true
end

-- 安全验证WiFi接口名
-- @param ifname string 接口名
-- @return string|nil 验证通过的接口名或nil
function M.validate_ifname(ifname)
    if not ifname or type(ifname) ~= "string" or ifname == "" then
        return nil
    end
    if ifname:match("[^%w%-_]") then
        return nil
    end
    if #ifname > 16 then
        return nil
    end
    return ifname
end

return M
```

**Step 2: 验证模块可加载**

在路由器上执行：
```bash
lua -e "local m = require('luci.utils.validate'); print(m.format_mac('aabbccddeeff'))"
```
Expected: 输出 `AA:BB:CC:DD:EE:FF`

**Step 3: 提交**

```bash
git add luasrc/utils/validate.lua
git commit -m "feat: 添加验证工具模块"
```

---

### Task 0.3: 创建 utils/format.lua

**Files:**
- Create: `luasrc/utils/format.lua`

**Step 1: 创建格式化模块**

```lua
--[[
    格式化工具模块
    提供字节、时间、MAC等格式化功能
]]--
local M = {}

-- 格式化字节数为人类可读格式
-- @param bytes number 字节数
-- @return string 格式化后的字符串（如 "1.5 GB"）
function M.format_bytes(bytes)
    if not bytes or type(bytes) ~= "number" or bytes < 0 then
        return "0 B"
    end
    
    local units = {"B", "KB", "MB", "GB", "TB", "PB"}
    local unit_index = 1
    local value = bytes
    
    while value >= 1024 and unit_index < #units do
        value = value / 1024
        unit_index = unit_index + 1
    end
    
    if unit_index == 1 then
        return string.format("%d %s", value, units[unit_index])
    else
        return string.format("%.2f %s", value, units[unit_index])
    end
end

-- 格式化时间为人类可读格式
-- @param timestamp number Unix时间戳
-- @return string 格式化后的时间字符串
function M.format_time(timestamp)
    if not timestamp or type(timestamp) ~= "number" then
        return "-"
    end
    return os.date("%Y-%m-%d %H:%M:%S", timestamp)
end

-- 格式化持续时间
-- @param seconds number 秒数
-- @return string 格式化后的持续时间（如 "2小时30分钟"）
function M.format_duration(seconds)
    if not seconds or type(seconds) ~= "number" or seconds < 0 then
        return "0秒"
    end
    
    local days = math.floor(seconds / 86400)
    local hours = math.floor((seconds % 86400) / 3600)
    local minutes = math.floor((seconds % 3600) / 60)
    local secs = seconds % 60
    
    local parts = {}
    if days > 0 then table.insert(parts, days .. "天") end
    if hours > 0 then table.insert(parts, hours .. "小时") end
    if minutes > 0 then table.insert(parts, minutes .. "分钟") end
    if secs > 0 and #parts == 0 then table.insert(parts, secs .. "秒") end
    
    return #parts > 0 and table.concat(parts, "") or "0秒"
end

-- 格式化网速
-- @param bytes_per_sec number 每秒字节数
-- @return string 格式化后的网速（如 "1.5 MB/s"）
function M.format_speed(bytes_per_sec)
    return M.format_bytes(bytes_per_sec) .. "/s"
end

-- HTML转义（防止XSS）
-- @param str string 原始字符串
-- @return string 转义后的字符串
function M.html_escape(str)
    if not str or type(str) ~= "string" then
        return ""
    end
    str = str:gsub("&", "&amp;")
    str = str:gsub("<", "&lt;")
    str = str:gsub(">", "&gt;")
    str = str:gsub('"', "&quot;")
    str = str:gsub("'", "&#39;")
    return str:sub(1, 64)
end

return M
```

**Step 2: 验证模块可加载**

```bash
lua -e "local m = require('luci.utils.format'); print(m.format_bytes(1536))"
```
Expected: 输出 `1.50 KB`

**Step 3: 提交**

```bash
git add luasrc/utils/format.lua
git commit -m "feat: 添加格式化工具模块"
```

---

### Task 0.4: 创建 utils/cache.lua

**Files:**
- Create: `luasrc/utils/cache.lua`

**Step 1: 创建缓存模块**

```lua
--[[
    缓存管理模块
    内存优先，文件可选，保护TF卡寿命
]]--
local M = {}

-- 配置
local CONFIG = {
    memory_ttl = 30,           -- 内存缓存TTL（秒）
    file_min_interval = 300,   -- 文件最小写入间隔（秒）
    cache_dir = "/tmp/router_assistant/cache/"
}

-- 内存缓存
local _memory_cache = {}
local _memory_time = {}

-- 文件写入时间记录
local _last_file_write = {}

-- 获取内存缓存
-- @param key string 缓存键
-- @return any|nil 缓存值或nil
function M.get_memory(key)
    local now = os.time()
    if _memory_cache[key] and (now - (_memory_time[key] or 0)) < CONFIG.memory_ttl then
        return _memory_cache[key]
    end
    return nil
end

-- 设置内存缓存
-- @param key string 缓存键
-- @param value any 缓存值
function M.set_memory(key, value)
    _memory_cache[key] = value
    _memory_time[key] = os.time()
end

-- 清除内存缓存
-- @param key string|nil 缓存键（nil则清除全部）
function M.clear_memory(key)
    if key then
        _memory_cache[key] = nil
        _memory_time[key] = nil
    else
        _memory_cache = {}
        _memory_time = {}
    end
end

-- 获取文件缓存
-- @param key string 缓存键
-- @return any|nil 缓存值或nil
function M.get_file(key)
    -- 先检查内存缓存
    local mem = M.get_memory(key)
    if mem then return mem end
    
    -- 读取文件
    local filepath = CONFIG.cache_dir .. key .. ".json"
    local fd = io.open(filepath, "r")
    if not fd then return nil end
    
    local content = fd:read("*a")
    fd:close()
    
    if not content or content == "" then
        return nil
    end
    
    local ok, data = pcall(function()
        return require("luci.jsonc").parse(content)
    end)
    
    if ok and data and data.value then
        M.set_memory(key, data.value)
        return data.value
    end
    
    return nil
end

-- 设置文件缓存
-- @param key string 缓存键
-- @param value any 缓存值
-- @param force boolean 是否强制写入（跳过间隔检查）
function M.set_file(key, value, force)
    -- 先更新内存缓存
    M.set_memory(key, value)
    
    -- 检查写入间隔（保护TF卡）
    local now = os.time()
    if not force and _last_file_write[key] and (now - _last_file_write[key]) < CONFIG.file_min_interval then
        return false
    end
    
    -- 确保目录存在
    os.execute("mkdir -p '" .. CONFIG.cache_dir .. "' 2>/dev/null")
    
    -- 写入文件
    local filepath = CONFIG.cache_dir .. key .. ".json"
    local fd = io.open(filepath, "w")
    if not fd then return false end
    
    local json = require("luci.jsonc")
    fd:write(json.stringify({value = value, time = now}))
    fd:close()
    
    _last_file_write[key] = now
    return true
end

-- 强制刷新到文件
-- @param key string 缓存键
function M.flush(key)
    local value = _memory_cache[key]
    if value then
        M.set_file(key, value, true)
    end
end

-- 获取缓存（自动选择内存或文件）
-- @param key string 缓存键
-- @param use_file boolean 是否使用文件缓存
-- @return any|nil 缓存值或nil
function M.get(key, use_file)
    if use_file then
        return M.get_file(key)
    else
        return M.get_memory(key)
    end
end

-- 设置缓存（自动选择内存或文件）
-- @param key string 缓存键
-- @param value any 缓存值
-- @param persist boolean 是否持久化到文件
function M.set(key, value, persist)
    M.set_memory(key, value)
    if persist then
        M.set_file(key, value, true)
    end
end

return M
```

**Step 2: 验证模块可加载**

```bash
lua -e "local m = require('luci.utils.cache'); m.set_memory('test', 'hello'); print(m.get_memory('test'))"
```
Expected: 输出 `hello`

**Step 3: 提交**

```bash
git add luasrc/utils/cache.lua
git commit -m "feat: 添加缓存管理模块"
```

---

## 阶段1：创建Model模块

### Task 1.1: 创建 model/oui.lua

**Files:**
- Create: `luasrc/model/oui.lua`

**Step 1: 创建OUI数据库模块**

```lua
--[[
    OUI数据库模块
    提供MAC厂商识别和设备类型判断功能
]]--
local M = {}

local validate = require("luci.utils.validate")
local json = require("luci.jsonc")

-- 缓存
local _oui_cache = nil
local _oui_cache_time = 0
local OUI_CACHE_TTL = 3600  -- 1小时

-- 内置OUI映射表（常用厂商）
local BUILTIN_OUI = {
    ["00:03:93"] = {vendor = "Apple", type = "phone"},
    ["00:1E:C2"] = {vendor = "Apple", type = "phone"},
    ["00:0A:27"] = {vendor = "Apple", type = "phone"},
    ["14:99:29"] = {vendor = "Apple", type = "phone"},
    ["18:65:90"] = {vendor = "Apple", type = "phone"},
    ["28:CF:DA"] = {vendor = "Apple", type = "phone"},
    ["34:15:9E"] = {vendor = "Apple", type = "phone"},
    ["64:DB:50"] = {vendor = "Apple", type = "phone"},
    ["78:4F:43"] = {vendor = "Apple", type = "phone"},
    ["88:66:FA"] = {vendor = "Apple", type = "phone"},
    ["A0:99:82"] = {vendor = "Apple", type = "phone"},
    ["DC:41:95"] = {vendor = "Apple", type = "phone"},
    ["00:05:69"] = {vendor = "VMware", type = "pc"},
    ["00:0C:29"] = {vendor = "VMware", type = "pc"},
    ["00:50:56"] = {vendor = "VMware", type = "pc"},
    ["08:00:27"] = {vendor = "VirtualBox", type = "pc"},
    ["52:54:00"] = {vendor = "QEMU", type = "pc"},
    ["00:21:6A"] = {vendor = "Samsung", type = "phone"},
    ["38:BC:1A"] = {vendor = "Samsung", type = "phone"},
    ["88:C6:63"] = {vendor = "Huawei", type = "phone"},
    ["34:CE:00"] = {vendor = "Xiaomi", type = "phone"},
    ["50:7E:5D"] = {vendor = "Xiaomi", type = "phone"},
    ["64:16:66"] = {vendor = "Xiaomi", type = "phone"},
    ["68:DF:DD"] = {vendor = "Xiaomi", type = "phone"},
    ["78:11:DC"] = {vendor = "Xiaomi", type = "phone"},
    ["7C:49:EB"] = {vendor = "Xiaomi", type = "phone"},
    ["88:C3:97"] = {vendor = "Xiaomi", type = "phone"},
    ["B4:E1:0F"] = {vendor = "Xiaomi", type = "phone"},
    ["B8:27:EB"] = {vendor = "RaspberryPi", type = "iot"},
    ["DC:A6:32"] = {vendor = "RaspberryPi", type = "iot"},
    ["00:26:AB"] = {vendor = "OPPO", type = "phone"},
    ["A4:45:19"] = {vendor = "OPPO", type = "phone"},
    ["00:1A:11"] = {vendor = "Google", type = "phone"},
    ["3C:5A:B4"] = {vendor = "Google", type = "phone"},
    ["54:60:09"] = {vendor = "Google", type = "phone"},
    ["00:22:43"] = {vendor = "HP", type = "pc"},
    ["3C:4A:92"] = {vendor = "HP", type = "pc"},
    ["00:1B:21"] = {vendor = "Lenovo", type = "pc"},
    ["00:1E:67"] = {vendor = "Lenovo", type = "pc"},
    ["00:21:CC"] = {vendor = "Lenovo", type = "pc"},
}

-- 加载外部OUI数据库
local function load_oui_database()
    local now = os.time()
    if _oui_cache and (now - _oui_cache_time) < OUI_CACHE_TTL then
        return _oui_cache
    end
    
    local paths = {
        "/usr/share/router-assistant/oui_database.json",
        "/usr/lib/lua/luci/oui_database.json",
    }
    
    for _, path in ipairs(paths) do
        local fd = io.open(path, "r")
        if fd then
            local content = fd:read("*a")
            fd:close()
            if content and content ~= "" then
                local ok, data = pcall(json.parse, content)
                if ok and data and data.brands then
                    _oui_cache = data.brands
                    _oui_cache_time = now
                    return _oui_cache
                end
            end
        end
    end
    
    return nil
end

-- 获取MAC厂商信息
-- @param mac string MAC地址
-- @return string|nil 厂商名称
-- @return string|nil 设备类型
function M.get_vendor(mac)
    if not mac then return nil, nil end
    
    local formatted = validate.format_mac(mac)
    if not formatted then return nil, nil end
    
    local oui = formatted:sub(1, 8)
    
    -- 检查内置表
    local info = BUILTIN_OUI[oui]
    if info then
        return info.vendor, info.type
    end
    
    -- 检查外部数据库
    local db = load_oui_database()
    if db then
        for brand, data in pairs(db) do
            if data.ouis then
                for _, db_oui in ipairs(data.ouis) do
                    if db_oui:upper() == oui then
                        return brand, data.type or "unknown"
                    end
                end
            end
        end
    end
    
    return nil, nil
end

-- 判断是否为本地管理MAC（虚拟接口）
-- @param mac string MAC地址
-- @return boolean 是否为本地管理MAC
function M.is_locally_administered(mac)
    if not mac then return false end
    local formatted = validate.format_mac(mac)
    if not formatted then return false end
    
    local first_byte = tonumber(formatted:sub(1, 2), 16)
    if not first_byte then return false end
    
    -- 本地管理MAC：第二个字节的第1位为1
    local second_char = formatted:sub(4, 4)
    local second_nibble = tonumber(second_char, 16)
    if not second_nibble then return false end
    
    return (second_nibble >= 2 and second_nibble <= 3) or
           (second_nibble >= 6 and second_nibble <= 7) or
           (second_nibble >= 10 and second_nibble <= 11) or
           (second_nibble >= 14 and second_nibble <= 15)
end

-- 根据主机名识别设备类型
-- @param hostname string 主机名
-- @return string 设备类型
function M.detect_device_type(hostname)
    if not hostname or hostname == "" then
        return "unknown"
    end
    
    local h = hostname:lower()
    
    -- 手机
    if h:match("iphone") or h:match("android") or h:match("redmi") or
       h:match("xiaomi") or h:match("huawei") or h:match("honor") or
       h:match("oppo") or h:match("vivo") or h:match("samsung") or
       h:match("pixel") or h:match("oneplus") or h:match("realme") then
        return "phone"
    end
    
    -- 平板
    if h:match("ipad") or h:match("tablet") or h:match("pad") then
        return "tablet"
    end
    
    -- 笔记本
    if h:match("macbook") or h:match("thinkpad") or h:match("laptop") then
        return "laptop"
    end
    
    -- 台式机
    if h:match("desktop") or h:match("windows") or h:match("pc") then
        return "desktop"
    end
    
    -- IoT设备
    if h:match("yeelight") or h:match("philips") or h:match("tuya") then
        return "iot"
    end
    
    -- 电视
    if h:match("tv") or h:match("television") then
        return "tv"
    end
    
    -- 路由器
    if h:match("router") or h:match("openwrt") then
        return "router"
    end
    
    return "unknown"
end

return M
```

**Step 2: 验证模块可加载**

```bash
lua -e "local m = require('luci.model.oui'); print(m.get_vendor('64:DB:50:XX:XX:XX'))"
```
Expected: 输出 `Apple phone`

**Step 3: 提交**

```bash
git add luasrc/model/oui.lua
git commit -m "feat: 添加OUI数据库模块"
```

---

### Task 1.2: 创建 model/storage.lua

**Files:**
- Create: `luasrc/model/storage.lua`

**Step 1: 创建存储模块**

```lua
--[[
    数据存储模块
    提供统一的存储接口，保护TF卡寿命
]]--
local M = {}

local cache = require("luci.utils.cache")
local json = require("luci.jsonc")

-- 数据目录
local DATA_DIR = "/tmp/router_assistant/data/"

-- 需要持久化的数据（写入TF卡）
local PERSIST_KEYS = {
    ["device_notes"] = true,
    ["blocked_macs"] = true,
    ["monthly_snapshot"] = true,
    ["security_whitelist"] = true,
}

-- 临时数据（仅内存缓存）
local TEMP_KEYS = {
    ["arp_table"] = true,
    ["wifi_clients"] = true,
    ["traffic_stats"] = true,
    ["dhcp_leases"] = true,
}

-- 确保数据目录存在
local function ensure_dir()
    os.execute("mkdir -p '" .. DATA_DIR .. "' 2>/dev/null")
end

-- 加载JSON文件
-- @param filename string 文件名（不含路径）
-- @return table|nil 解析后的数据或nil
function M.load(filename)
    -- 先检查内存缓存
    local cached = cache.get_memory(filename)
    if cached then
        return cached
    end
    
    -- 检查是否需要从文件加载
    if not PERSIST_KEYS[filename] then
        return nil
    end
    
    -- 从文件加载
    local filepath = DATA_DIR .. filename .. ".json"
    local fd = io.open(filepath, "r")
    if not fd then
        return nil
    end
    
    local content = fd:read("*a")
    fd:close()
    
    if not content or content == "" then
        return nil
    end
    
    local ok, data = pcall(json.parse, content)
    if ok and data then
        cache.set_memory(filename, data)
        return data
    end
    
    return nil
end

-- 保存JSON文件
-- @param filename string 文件名（不含路径）
-- @param data table 要保存的数据
-- @param immediate boolean 是否立即写入（跳过间隔检查）
-- @return boolean 是否成功
function M.save(filename, data, immediate)
    -- 更新内存缓存
    cache.set_memory(filename, data)
    
    -- 检查是否需要持久化
    if not PERSIST_KEYS[filename] then
        return true
    end
    
    -- 检查是否立即写入
    if not immediate then
        -- 使用缓存的文件写入（受间隔限制）
        return cache.set_file(filename, data, false)
    end
    
    -- 立即写入
    ensure_dir()
    local filepath = DATA_DIR .. filename .. ".json"
    local fd = io.open(filepath, "w")
    if not fd then
        return false
    end
    
    fd:write(json.stringify(data))
    fd:close()
    
    -- 更新文件缓存记录
    cache.set_file(filename, data, true)
    
    return true
end

-- 删除数据文件
-- @param filename string 文件名
-- @return boolean 是否成功
function M.delete(filename)
    -- 清除内存缓存
    cache.clear_memory(filename)
    
    -- 删除文件
    local filepath = DATA_DIR .. filename .. ".json"
    os.remove(filepath)
    
    return true
end

-- 获取存储路径
-- @return string 数据目录路径
function M.get_data_dir()
    return DATA_DIR
end

return M
```

**Step 2: 验证模块可加载**

```bash
lua -e "local m = require('luci.model.storage'); m.save('test', {a=1}, true); print(m.load('test').a)"
```
Expected: 输出 `1`

**Step 3: 提交**

```bash
git add luasrc/model/storage.lua
git commit -m "feat: 添加数据存储模块"
```

---

## 阶段2：创建Controller模块（设备管理）

### Task 2.1: 创建 controller/devices.lua

**Files:**
- Create: `luasrc/controller/devices.lua`

**Step 1: 创建设备管理模块**

```lua
--[[
    设备管理API模块
    提供设备列表、踢出设备、恢复设备等功能
]]--
local M = {}

local validate = require("luci.utils.validate")
local format = require("luci.utils.format")
local storage = require("luci.model.storage")
local oui = require("luci.model.oui")

-- 获取设备列表
-- @return table 设备列表
function M.get_devices()
    local util = require("luci.util")
    local json = require("luci.jsonc")
    
    -- 调用infocd获取设备数据
    local output = util.exec("ubus call infocd terminal 2>/dev/null")
    if not output or output == "" then
        return {}
    end
    
    local ok, data = pcall(json.parse, output)
    if not ok or not data or not data.client then
        return {}
    end
    
    local devices = {}
    local dhcp_leases = M._load_dhcp_leases()
    
    for mac, client in pairs(data.client) do
        local formatted_mac = validate.format_mac(mac)
        if formatted_mac then
            local hostname = client.hostname or dhcp_leases[formatted_mac] or "Unknown"
            local ip = client.ipaddr or "-"
            local ifname = client.ifname or ""
            local is_wifi = M._is_wifi_device(client, mac)
            local vendor, device_type = oui.get_vendor(formatted_mac)
            
            if not device_type or device_type == "unknown" then
                device_type = oui.detect_device_type(hostname)
            end
            
            table.insert(devices, {
                mac = formatted_mac,
                hostname = format.html_escape(hostname),
                ip = validate.validate_ip(ip) or "-",
                ifname = validate.validate_ifname(ifname) or "",
                is_wifi = is_wifi,
                device_type = device_type or "unknown",
                vendor = vendor or "Unknown",
                online = true
            })
        end
    end
    
    return devices
end

-- 加载DHCP租约
-- @return table MAC->主机名映射
function M._load_dhcp_leases()
    local leases = {}
    local fd = io.open("/tmp/dhcp.leases", "r")
    if not fd then return leases end
    
    for line in fd:lines() do
        local parts = {}
        for part in line:gmatch("%S+") do
            table.insert(parts, part)
        end
        if #parts >= 4 then
            local mac = validate.format_mac(parts[2])
            if mac then
                leases[mac] = parts[4]
            end
        end
    end
    fd:close()
    
    return leases
end

-- 判断是否为WiFi设备
-- @param client table 客户端信息
-- @param mac string MAC地址
-- @return boolean 是否为WiFi设备
function M._is_wifi_device(client, mac)
    if client.type == "wireless" then
        return true
    end
    
    local ifname = client.ifname or ""
    local wifi_prefixes = {"ra", "rai", "wlan", "apcli"}
    for _, prefix in ipairs(wifi_prefixes) do
        if ifname:match("^" .. prefix) then
            return true
        end
    end
    
    return false
end

-- 踢出设备
-- @param mac string MAC地址
-- @return boolean, string 是否成功, 消息
function M.kick_device(mac)
    local formatted_mac = validate.format_mac(mac)
    if not formatted_mac then
        return false, "无效的MAC地址"
    end
    
    -- 添加到黑名单
    local blocked = storage.load("blocked_macs") or {devices = {}}
    blocked.devices[formatted_mac] = {
        blocked_at = os.time(),
        reason = "手动踢出"
    }
    storage.save("blocked_macs", blocked, true)
    
    -- 执行iptables规则（后台执行）
    local cmd = string.format(
        "iptables -I INPUT -m mac --mac-source %s -j DROP 2>/dev/null; " ..
        "iptables -I FORWARD -m mac --mac-source %s -j DROP 2>/dev/null",
        formatted_mac, formatted_mac
    )
    require("luci.util").exec(cmd)
    
    return true, "设备已踢出"
end

-- 恢复设备
-- @param mac string MAC地址
-- @return boolean, string 是否成功, 消息
function M.enable_device(mac)
    local formatted_mac = validate.format_mac(mac)
    if not formatted_mac then
        return false, "无效的MAC地址"
    end
    
    -- 从黑名单移除
    local blocked = storage.load("blocked_macs") or {devices = {}}
    blocked.devices[formatted_mac] = nil
    storage.save("blocked_macs", blocked, true)
    
    -- 删除iptables规则
    local cmd = string.format(
        "iptables -D INPUT -m mac --mac-source %s -j DROP 2>/dev/null; " ..
        "iptables -D FORWARD -m mac --mac-source %s -j DROP 2>/dev/null",
        formatted_mac, formatted_mac
    )
    require("luci.util").exec(cmd)
    
    return true, "设备已恢复"
end

-- 获取被屏蔽的设备列表
-- @return table 被屏蔽的设备列表
function M.get_blocked_devices()
    local blocked = storage.load("blocked_macs") or {devices = {}}
    local result = {}
    
    for mac, info in pairs(blocked.devices or {}) do
        table.insert(result, {
            mac = mac,
            blocked_at = info.blocked_at,
            reason = info.reason or ""
        })
    end
    
    return result
end

return M
```

**Step 2: 验证模块可加载**

```bash
lua -e "local m = require('luci.controller.devices'); print(#m.get_devices())"
```
Expected: 输出设备数量（数字）

**Step 3: 提交**

```bash
git add luasrc/controller/devices.lua
git commit -m "feat: 添加设备管理API模块"
```

---

## 阶段3：修改主入口

### Task 3.1: 更新主控制器使用新模块

**Files:**
- Modify: `luasrc/controller/router_assistant.lua`

**Step 1: 在文件开头添加新模块引用**

在现有代码的 `module()` 定义之后添加：

```lua
-- 新模块引用
local validate = require("luci.utils.validate")
local format_utils = require("luci.utils.format")
local cache = require("luci.utils.cache")
local devices_api = require("luci.controller.devices")
```

**Step 2: 添加新的API路由（与旧API并行）**

在 `index()` 函数中添加：

```lua
-- 新版API路由（带_v2后缀，与旧API并行）
entry({"admin", "status", "router_assistant", "v2", "get_devices"}, call("api_v2_get_devices")).leaf = true
entry({"admin", "status", "router_assistant", "v2", "kick_device"}, post("api_v2_kick_device")).leaf = true
entry({"admin", "status", "router_assistant", "v2", "enable_device"}, post("api_v2_enable_device")).leaf = true
```

**Step 3: 添加新版API实现**

```lua
-- 新版API：获取设备列表
function api_v2_get_devices()
    if not validate.require_csrf() then return end
    
    local response_data
    local ok, err = pcall(function()
        local devices = devices_api.get_devices()
        response_data = {
            code = 0,
            data = {devices = devices},
            timestamp = os.time()
        }
    end)
    
    if not ok then
        response_data = {
            code = -1,
            message = "获取设备列表失败",
            details = tostring(err),
            timestamp = os.time()
        }
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- 新版API：踢出设备
function api_v2_kick_device()
    if not validate.require_csrf() then return end
    
    local mac = luci.http.formvalue("mac")
    local success, message = devices_api.kick_device(mac)
    
    local response_data = {
        code = success and 0 or -1,
        message = message,
        timestamp = os.time()
    }
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end

-- 新版API：恢复设备
function api_v2_enable_device()
    if not validate.require_csrf() then return end
    
    local mac = luci.http.formvalue("mac")
    local success, message = devices_api.enable_device(mac)
    
    local response_data = {
        code = success and 0 or -1,
        message = message,
        timestamp = os.time()
    }
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response_data)
end
```

**Step 4: 验证新旧API返回相同数据**

在路由器上测试：
```bash
# 测试旧API
curl "http://localhost/cgi-bin/luci/admin/status/router_assistant/get_devices?token=xxx"

# 测试新API
curl "http://localhost/cgi-bin/luci/admin/status/router_assistant/v2/get_devices?token=xxx"
```

Expected: 两个API返回的设备列表一致

**Step 5: 提交**

```bash
git add luasrc/controller/router_assistant.lua
git commit -m "feat: 添加新版API路由，与旧API并行运行"
```

---

## 阶段4：验证和清理

### Task 4.1: 功能验证

**Step 1: 验证所有API正常工作**

测试清单：
- [ ] 获取设备列表
- [ ] 踢出设备
- [ ] 恢复设备
- [ ] 获取流量统计
- [ ] 获取WiFi信息
- [ ] 安全检测

**Step 2: 验证TF卡写入频率**

```bash
# 监控文件写入
inotifywait -m /tmp/router_assistant/
```

Expected: 写入间隔 >= 5分钟

**Step 3: 验证前端页面正常**

打开路由器管理页面，检查所有功能是否正常。

---

### Task 4.2: 最终提交

**Step 1: 更新设计文档**

```bash
git add docs/plans/2026-05-02-refactor-design.md
git commit -m "docs: 更新重构设计文档"
```

**Step 2: 创建版本标签**

```bash
git tag -a v2.0.0-refactor -m "重构版本：模块化架构"
```

---

## 回滚方案

如果出现问题，按以下步骤回滚：

1. **阶段0-1回滚**：删除新创建的文件
   ```bash
   rm -rf luasrc/utils/ luasrc/model/oui.lua luasrc/model/storage.lua
   git checkout .
   ```

2. **阶段2回滚**：禁用新版API路由
   ```bash
   git revert HEAD
   ```

3. **阶段3回滚**：恢复旧版入口文件
   ```bash
   git checkout HEAD~1 -- luasrc/controller/router_assistant.lua
   ```
