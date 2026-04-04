--[[
  JSON 适配器 - 提供与 luci.jsonc 兼容的接口
  用于 C2000-788 等没有 luci.jsonc 的固件
  实现基本的 JSON 编码/解码功能
]]

local json = {}

function json.encode(data)
    local function esc(c)
        local escape_map = {
            ["\""] = "\\\"",
            ["\\"] = "\\\\",
            ["/"] = "\\/",
            ["\b"] = "\\b",
            ["\f"] = "\\f",
            ["\n"] = "\\n",
            ["\r"] = "\\r",
            ["\t"] = "\\t"
        }
        return escape_map[c] or string.format("\\u%04x", string.byte(c))
    end

    local function encode_value(val, indent, depth)
        if indent == nil then indent = "" end
        if depth == nil then depth = 0 end

        local spaces = string.rep("  ", depth)

        if type(val) == "nil" then
            return "null"
        elseif type(val) == "boolean" then
            return val and "true" or "false"
        elseif type(val) == "number" then
            if val ~= val then
                return "null"
            elseif val == math.huge then
                return "null"
            elseif val == -math.huge then
                return "null"
            else
                return string.format("%.14g", val)
            end
        elseif type(val) == "string" then
            return '"' .. val:gsub('[\\"/%c]', esc) .. '"'
        elseif type(val) == "table" then
            local is_array = #val > 0 or next(val) == nil
            local keys = {}
            local key_count = 0

            if is_array then
                for i = 1, #val do
                    local item = encode_value(val[i], indent, depth + 1)
                    if item == nil then return nil end
                    table.insert(keys, item)
                end
                return "[" .. table.concat(keys, ",") .. "]"
            else
                for k, v in pairs(val) do
                    if type(k) ~= "string" then
                        return nil
                    end
                    local key_str = '"' .. k:gsub('[\\"/%c]', esc) .. '"'
                    local val_str = encode_value(v, indent, depth + 1)
                    if val_str == nil then return nil end
                    table.insert(keys, key_str .. ":" .. val_str)
                end
                return "{" .. table.concat(keys, ",") .. "}"
            end
        else
            return nil
        end
    end

    return encode_value(data)
end

function json.decode(json_str)
    if type(json_str) ~= "string" then
        return nil, "expected string"
    end

    local pos = 1
    local len = #json_str

    local function skip_whitespace()
        while pos <= len do
            local c = json_str:sub(pos, pos)
            if c == " " or c == "\t" or c == "\n" or c == "\r" then
                pos = pos + 1
            else
                break
            end
        end
    end

    local function parse_string()
        if json_str:sub(pos, pos) ~= '"' then
            return nil, "expected string"
        end
        pos = pos + 1

        local result = {}
        while pos <= len do
            local c = json_str:sub(pos, pos)

            if c == '"' then
                pos = pos + 1
                return table.concat(result)
            elseif c == "\\" then
                pos = pos + 1
                if pos > len then return nil, "unexpected end" end
                local esc_c = json_str:sub(pos, pos)
                local escape_map = {
                    ['"'] = '"',
                    ['\\'] = '\\',
                    ['/'] = '/',
                    ['b'] = '\b',
                    ['f'] = '\f',
                    ['n'] = '\n',
                    ['r'] = '\r',
                    ['t'] = '\t'
                }
                if escape_map[esc_c] then
                    table.insert(result, escape_map[esc_c])
                    pos = pos + 1
                elseif esc_c == 'u' then
                    pos = pos + 1
                    local hex = json_str:sub(pos, pos + 3)
                    if #hex ~= 4 or not hex:match("^[0-9a-fA-F]+$") then
                        return nil, "invalid unicode"
                    end
                    local code = tonumber(hex, 16)
                    if code then
                        table.insert(result, string.char(code))
                    end
                    pos = pos + 4
                else
                    return nil, "invalid escape"
                end
            elseif c == "\n" or c == "\r" then
                return nil, "unexpected newline"
            else
                table.insert(result, c)
                pos = pos + 1
            end
        end

        return nil, "unterminated string"
    end

    local function parse_number()
        local start = pos
        local has_decimal = false
        local has_exponent = false

        if json_str:sub(pos, pos) == "-" then
            pos = pos + 1
        end

        while pos <= len do
            local c = json_str:sub(pos, pos)
            if c:match("[0-9]") then
                pos = pos + 1
            elseif c == "." and not has_decimal then
                has_decimal = true
                pos = pos + 1
            elseif (c == "e" or c == "E") and not has_exponent then
                has_exponent = true
                pos = pos + 1
                if json_str:sub(pos, pos) == "+" or json_str:sub(pos, pos) == "-" then
                    pos = pos + 1
                end
            else
                break
            end
        end

        local num_str = json_str:sub(start, pos - 1)
        local num = tonumber(num_str)
        if num then
            return num
        else
            return nil, "invalid number"
        end
    end

    local function parse_literal(lit)
        local expected = json_str:sub(pos, pos + #lit - 1)
        if expected == lit then
            pos = pos + #lit
            if lit == "true" then return true end
            if lit == "false" then return false end
            if lit == "null" then return nil end
        end
        return nil, "expected " .. lit
    end

    local function parse_array()
        if json_str:sub(pos, pos) ~= "[" then
            return nil, "expected ["
        end
        pos = pos + 1
        skip_whitespace()

        local arr = {}
        if json_str:sub(pos, pos) == "]" then
            pos = pos + 1
            return arr
        end

        while true do
            skip_whitespace()
            local val, err = parse_value()
            if val == nil and err then
                return nil, err
            end
            table.insert(arr, val)
            skip_whitespace()

            if json_str:sub(pos, pos) == "]" then
                pos = pos + 1
                return arr
            elseif json_str:sub(pos, pos) == "," then
                pos = pos + 1
            else
                return nil, "expected , or ]"
            end
        end
    end

    local function parse_object()
        if json_str:sub(pos, pos) ~= "{" then
            return nil, "expected {"
        end
        pos = pos + 1
        skip_whitespace()

        local obj = {}
        if json_str:sub(pos, pos) == "}" then
            pos = pos + 1
            return obj
        end

        while true do
            skip_whitespace()
            if json_str:sub(pos, pos) ~= '"' then
                return nil, "expected key"
            end
            local key, err = parse_string()
            if key == nil then
                return nil, err
            end
            skip_whitespace()

            if json_str:sub(pos, pos) ~= ":" then
                return nil, "expected :"
            end
            pos = pos + 1

            skip_whitespace()
            local val, err = parse_value()
            if val == nil and err then
                return nil, err
            end
            obj[key] = val
            skip_whitespace()

            if json_str:sub(pos, pos) == "}" then
                pos = pos + 1
                return obj
            elseif json_str:sub(pos, pos) == "," then
                pos = pos + 1
            else
                return nil, "expected , or }"
            end
        end
    end

    function parse_value()
        skip_whitespace()
        if pos > len then
            return nil, "unexpected end"
        end

        local c = json_str:sub(pos, pos)
        if c == '"' then
            return parse_string()
        elseif c == "[" then
            return parse_array()
        elseif c == "{" then
            return parse_object()
        elseif c == "t" then
            return parse_literal("true")
        elseif c == "f" then
            return parse_literal("false")
        elseif c == "n" then
            return parse_literal("null")
        elseif c:match("[0-9-]") then
            return parse_number()
        else
            return nil, "unexpected character: " .. c
        end
    end

    local ok, result = pcall(function()
        skip_whitespace()
        local val = parse_value()
        skip_whitespace()
        if pos <= len then
            return nil, "trailing garbage"
        end
        return val
    end)

    if ok then
        return result
    else
        return nil, result
    end
end

return json
