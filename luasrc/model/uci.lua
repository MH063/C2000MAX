--[[
LuCI - Lua Configuration Interface
UCI model helper for router-assistant
]]--

module("luci.model.router_assistant_uci", package.seeall)

local uci = require("uci")

function get_cursor()
	return uci.cursor()
end

function get_config(name, section, option)
	local c = uci.cursor()
	if option then
		return c:get(name, section, option)
	end
	return c:get_all(name, section)
end

function set_config(name, section, option, value)
	local c = uci.cursor()
	c:set(name, section, option, value)
	return c:save(name)
end

function add_config(name, type_name, section)
	local c = uci.cursor()
	local s = c:section(name, type_name)
	c:save(name)
	return s
end

function foreach_config(name, type_name, callback)
	local c = uci.cursor()
	c:foreach(name, type_name, function(s)
		callback(s)
		return true
	end)
end