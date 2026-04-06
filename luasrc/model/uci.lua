--[[
LuCI - Lua Configuration Interface
UCI model helper for router-assistant
]]--

local M = {}

local uci_cursor = nil

local function get_uci()
    if not uci_cursor then
        local uci_ok, uci_lib = pcall(require, "uci")
        if not uci_ok then
            return nil
        end
        uci_cursor = uci_lib.cursor()
    end
    return uci_cursor
end

function M.get_cursor()
    return get_uci()
end

function M.get_config(name, section, option)
    local c = get_uci()
    if not c then return nil end
    
    if option then
        return c:get(name, section, option)
    end
    return c:get_all(name, section)
end

function M.set_config(name, section, option, value)
    local c = get_uci()
    if not c then return end
    
    c:set(name, section, option, value)
    return c:save(name)
end

function M.add_config(name, type_name, section)
    local c = get_uci()
    if not c then return nil end
    
    local s = c:section(name, type_name)
    c:save(name)
    return s
end

function M.foreach_config(name, type_name, callback)
    local c = get_uci()
    if not c or not callback then return end
    
    c:foreach(name, type_name, function(s)
        callback(s)
        return true
    end)
end

return M
