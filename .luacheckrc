-- ============================================================
-- Luacheck 配置文件
-- 用于 GitHub Actions 中的 Lua 代码质量检查
-- 版本: v1.0.0
-- ============================================================

-- 全局变量定义（OpenWrt/LuCI 环境）
globals = {
    "luci",
    "nixio",
    "util",
    "uci",
    "json",
    "io",
    "os",
    "string",
    "table",
    "math",
    "package",
    "debug",
    "coroutine",
    "bit32",
    "_G",
    "pairs",
    "ipairs",
    "print",
    "type",
    "tostring",
    "tonumber",
    "error",
    "assert",
    "pcall",
    "xpcall",
    "rawget",
    "rawset",
    "setmetatable",
    "getmetatable",
    "next",
    "select",
    "unpack",  -- Lua 5.1 compatibility
    "load",
    "loadfile",
    "loadstring",
    "dofile",
    "require",
    "module"
}

-- 忽略的变量（未定义但可接受）
read_globals = {
    -- OpenWrt 系统库
    "posix",
    
    -- LuCI 框架
    "luci.dispatcher",
    "luci.template",
    "luci.http",
    "luci.sys",
    "luci.model.uci",
    "luci.jsonc",
    "luci.i18n",
    
    -- 自定义模块
    "M",  -- 模块返回表
}

-- 未使用的变量警告级别
unused = true

-- 重新定义的变量警告
redefined = false

-- 全局变量访问限制
global = false

-- 忽略的自定义文件或模式
exclude_files = {
    "openssl-3.0.0/**",
    "**/node_modules/**",
    ".git/**"
}

-- 允许的行长度（默认120）
max_line_length = 200

-- 允许的代码复杂度
max cyclomatic_complexity = 50

-- 忽略特定警告
ignore = {
    "611",  -- line contains trailing whitespace（尾随空格）
    "612",  -- line contains only whitespace（仅空白行）
    "613",  -- trailing whitespace in string（字符串中尾随空格）
    "614",  # warning at end of file（文件末尾警告）
}

-- 标准库版本
std = "lua53c"

-- 自定义规则
allow_defined = true
allow_defined_top = true
module = true

-- 格式化选项
format = "quiet"  -- 或 "standard", "gnu"
