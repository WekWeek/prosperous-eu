code = [=[

LUA_CODE_COOKIE

]=]

thunk = "code = [=[" .. code .. "]=]\n" .. [[
    local status, err = pcall(function ()
        local mt = getmetatable(_G)
        mt.__newindex = function (t, n, v)
            rawset(t, n, v)
        end
        mt.__index = function (t, n)
            return rawget(t, n)
        end
        
        local func = loadstring(code)
        if func ~= nil then
            func()
        else
            DisplayError("SYNTAX ERROR IDIOT")
        end
    end)
    DisplayError("ERROR: " .. tostring(status) .. " " .. tostring(err))
]]

loadstring(thunk)()
DisplayError("FOOL")
