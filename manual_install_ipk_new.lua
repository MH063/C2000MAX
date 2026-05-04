-- 手动安装IPK包（不使用opkg）
-- 支持两种格式：tar.gz (gzip) 和 Debian ar (标准OpenWrt)
local function manual_install_ipk(ipk_path, pkg_name)
    local util = require("luci.util")
    local nixio = require("nixio")
    local tmp_dir = "/tmp/ipk_install_" .. pkg_name
    util.exec("rm -rf '" .. tmp_dir .. "' 2>/dev/null")
    util.exec("mkdir -p '" .. tmp_dir .. "'")
    
    -- 检测文件是否存在且可读
    local check_file = util.exec("test -f '" .. ipk_path .. "' && test -r '" .. ipk_path .. "' && echo yes || echo no")
    if not check_file or not check_file:match("yes") then
        nixio.syslog("err", "[DNS加密] IPK文件不存在或不可读: " .. ipk_path)
        util.exec("rm -rf '" .. tmp_dir .. "' 2>/dev/null")
        return false
    end
    
    -- 获取文件大小用于日志
    local file_size = util.exec("stat -c%s '" .. ipk_path .. "' 2>/dev/null") or "0"
    nixio.syslog("info", "[DNS加密] 开始安装: " .. pkg_name .. " (大小: " .. (file_size:gsub("%s+", "")) .. " bytes)")
    
    -- 尝试方式1: 用tar xf解压（兼容Debian ar格式）
    local extract_cmd = string.format(
        "cd '%s' && tar xf '%s' 2>/dev/null && echo SUCCESS || echo FAILED",
        tmp_dir, ipk_path
    )
    local result = util.exec(extract_cmd)
    
    -- 如果tar xf失败，尝试tar xzf（显式gzip解压）
    if not result or not result:match("SUCCESS") then
        extract_cmd = string.format(
            "cd '%s' && tar xzf '%s' 2>/dev/null && echo SUCCESS || echo FAILED",
            tmp_dir, ipk_path
        )
        result = util.exec(extract_cmd)
    end
    
    if not result or not result:match("SUCCESS") then
        nixio.syslog("err", "[DNS加密] 解压IPK失败: " .. ipk_path)
        util.exec("rm -rf '" .. tmp_dir .. "' 2>/dev/null")
        return false
    end
    
    -- 检查解压后的内容
    local list_result = util.exec("ls -la '" .. tmp_dir .. "' 2>/dev/null") or ""
    nixio.syslog("info", "[DNS加密] 解压内容: " .. list_result:gsub("\n", "; "))
    
    -- 提取data.tar.gz到根目录
    if util.exec("test -f '" .. tmp_dir .. "/data.tar.gz' && echo yes || echo no"):match("yes") then
        util.exec("tar xzf '" .. tmp_dir .. "/data.tar.gz" -C / 2>/dev/null")
        nixio.syslog("info", "[DNS加密] 已提取data.tar.gz")
    else
        nixio.syslog("warning", "[DNS加密] 未找到data.tar.gz")
    end
    
    -- 提取control.tar.gz到opkg/info目录
    util.exec("mkdir -p /usr/lib/opkg/info 2>/dev/null")
    if util.exec("test -f '" .. tmp_dir .. "/control.tar.gz' && echo yes || echo no"):match("yes") then
        util.exec("tar xzf '" .. tmp_dir .. "/control.tar.gz" -C /usr/lib/opkg/info/ 2>/dev/null")
        nixio.syslog("info", "[DNS加密] 已提取control.tar.gz")
    end
    
    -- 执行postinst脚本
    local postinst = tmp_dir .. "/control/postinst"
    if util.exec("test -f '" .. postinst .. "' && echo yes || echo no"):match("yes") then
        util.exec("sh '" .. postinst .. "' install 2>/dev/null")
        nixio.syslog("info", "[DNS加密] 已执行postinst脚本")
    end
    
    util.exec("rm -rf '" .. tmp_dir .. "' 2>/dev/null")
    nixio.syslog("info", "[DNS加密] 手动安装完成: " .. pkg_name)
    return true
end