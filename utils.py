import unicorn
import unicorn.x86_const

def dump_regs(mu, address, size):
    f = open("dump_regs","a+")
    f.write(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n" %(address, size))
    rax = mu.reg_read(unicorn.x86_const.UC_X86_REG_RAX)
    rbx = mu.reg_read(unicorn.x86_const.UC_X86_REG_RBX)
    rcx = mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
    rdx = mu.reg_read(unicorn.x86_const.UC_X86_REG_RDX)
    rsi = mu.reg_read(unicorn.x86_const.UC_X86_REG_RSI)
    rdi = mu.reg_read(unicorn.x86_const.UC_X86_REG_RDI)
    rbp = mu.reg_read(unicorn.x86_const.UC_X86_REG_RBP)
    rsp = mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
    rip = mu.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
    r8 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R8)
    r9 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R9)
    r10 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R10)
    r11 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R11)
    r12 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R12)
    r13 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R13)
    r14 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R14)
    r15 = mu.reg_read(unicorn.x86_const.UC_X86_REG_R15)

    f.write(">>> RAX = 0x%x\n" %rax)
    f.write(">>> RBX = 0x%x\n" %rbx)
    f.write(">>> RCX = 0x%x\n" %rcx)
    f.write(">>> RDX = 0x%x\n" %rdx)
    f.write(">>> RSI = 0x%x\n" %rsi)
    f.write(">>> RDI = 0x%x\n" %rdi)
    f.write(">>> RBP = 0x%x\n" %rbp)
    f.write(">>> RSP = 0x%x\n" %rsp)
    f.write(">>> RIP = 0x%x\n" %rip)
    f.write(">>> R8 = 0x%x\n" %r8)
    f.write(">>> R9 = 0x%x\n" %r9)
    f.write(">>> R10 = 0x%x\n" %r10)
    f.write(">>> R11 = 0x%x\n" %r11)
    f.write(">>> R12 = 0x%x\n" %r12)
    f.write(">>> R13 = 0x%x\n" %r13)
    f.write(">>> R14 = 0x%x\n" %r14)
    f.write(">>> R15 = 0x%x\n" %r15)

def dump_mapping(mu, addr, size):
    f = open("dump_mappings", "a+")
    f.write("Dumping the mapping at the address: " + str(hex(addr)) + ", size: " + str(hex(size)) + "\n")
    memhex = str(mu.mem_read(addr, size)).encode('hex')
    f.write(memhex + "\n")

def dump_at_addr(mu, addr, length):
    print "Dumping the mapping at the address: " + str(hex(addr)) + ", length: " + str(hex(length))
    memhex = str(mu.mem_read(addr, length)).encode('hex')
    print memhex

