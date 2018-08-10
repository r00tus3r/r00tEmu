import pylibelf
import unicorn
import logging
import unicorn.x86_const
import argparse
import utils

#Setting the logging level
def logging_level(log):
    if log != None:
        loglevel = log
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            logging.warning('Invalid log level: %s', loglevel)
            logging.warning('The default log level(i.e. INFO) is taken')
            return 20
        return numeric_level
    else:
        return 20

#Tracing Instructions
def hook_code(mu, address, size, user_data):
    print ">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size)
    utils.dump_regs(mu, address, size)

#Initializing registers
def init_reg(mu):
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RBX, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RSI, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RBP, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, 0x7fffffffe0a0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R8, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R9, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R10, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R11, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R12, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R13, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R14, 0x0)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_R15, 0x0)

#Retrieving the program header details
def ret_program_headers(elf, addr, vaddr, memsz, filesz, offset, logger):
    for phdr in elf.PhdrTable:
        for _, segment_value in pylibelf.elfconstants.elf_segment_types:
            if phdr.p_type.value == segment_value:
                logger.debug(_ + ":" + str(hex(phdr.p_paddr.value)) + ":" +
                             str(hex(phdr.p_memsz.value)))
                addr.append(phdr.p_paddr.value)
                vaddr.append(phdr.p_vaddr.value)
                memsz.append(phdr.p_memsz.value)
                filesz.append(phdr.p_filesz.value)
                offset.append(phdr.p_offset.value)

#Memory mapping
def mmap(mu, aligned_addr, aligned_size, logger):
    try:
        for i in xrange(len(aligned_addr)):
            mu.mem_map(aligned_addr[i], aligned_size[i])
            logger.debug(hex(aligned_addr[i]) + ":" + hex(aligned_size[i]))
        mu.mem_map(0x00007ffffffde000, 0x21000)
    except unicorn.unicorn.UcError:
        logger.error("Invalid argument (UC_ERR_ARG)")
        exit(0)

#Reading from the elf file and then writing into the memory mapped area
def mwrite(mu, elf, offset, filesz, vaddr, logger):
    for i in xrange(len(offset)):
        data = elf.readDataAtOffset(offset[i], filesz[i])
        logger.debug(hex(vaddr[i]))
        mu.mem_write(vaddr[i], data)
        utils.dump_mapping(mu, vaddr[i], filesz[i])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Name of file to be emulated")
    parser.add_argument("-log", default=None,
                        choices=["DEBUG", "INFO", "WARNING",
                                 "ERROR", "CRITICAL"],
                        help="Preffered logging level")
    args = parser.parse_args()
    FORMAT = "[%(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
    logging.basicConfig(format=FORMAT, level=logging_level(args.log))
    logger = logging.getLogger(__name__)

    logger.info("Started")
    elf = pylibelf.ELF(args.filename)
    open('dump_regs', 'w').close()
    open('dump_mappings', 'w').close()
    logger.debug("Entry Point: " + str(hex(elf.elfHdr.e_entry.value)))

    addr, offset, memsz, filesz, vaddr, aligned_addr, aligned_size = [[] for _ in xrange(7)]

    logger.info("Retrieving the program headers")
    ret_program_headers(elf, addr, vaddr, memsz, filesz, offset, logger)

    roundoff_addr = lambda val: val if val % 4096 == 0 else ((val/4096)*4096)
    roundoff_size = lambda val: val if val % 4096 == 0 else ((val/4096)*4096 + 2*4096)

    logger.info("Rounding off the Vaddr and Memsz")
    aligned_addr.append(roundoff_addr(vaddr[0]))
    aligned_size.append(roundoff_size(memsz[0]))

    logger.info("Consolidating mappings")
    for i in xrange(1, len(vaddr)):
        tmp_addr = roundoff_addr(vaddr[i])
        tmp_sz = roundoff_size(memsz[i])
        flag = 0
        for j in xrange(len(aligned_addr)):
            if aligned_addr[j] == tmp_addr:
                flag = 1
                if vaddr[i] + memsz[i] > aligned_addr[j] + aligned_size[j]:
                    tmp_sz = roundoff_size((tmp_addr + memsz[i]) -
                                           (aligned_addr[j] + aligned_size[j]))
                    aligned_size[j] += tmp_sz
                break
        if flag == 0:
            aligned_addr.append(tmp_addr)
            aligned_size.append(tmp_sz)

    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    logger.info("Memory mapping")
    mmap(mu, aligned_addr, aligned_size, logger)

    logger.info("Writing into the memory mapped area at their respective offsets")
    mwrite(mu, elf, offset, filesz, vaddr, logger)

    '''logger.info("Retrieving the different sections and also writing into memory")
    for sec in elf.ShdrTable:
        logger.debug(sec.sectionName + ":" + str(hex(sec.sh_addr.value)) +
                     ":" + str(hex(sec.sh_size.value)))
        if sec.sh_addr.value == 0x0:
            continue
        data = elf.readDataAtOffset(sec.sh_offset.value, sec.sh_size.value)
        mu.mem_write(sec.sh_addr.value, data)'''

    logger.info("Initializing registers")
    init_reg(mu)

    utils.dump_at_addr(mu, 0x400ce0, 0x100, logger)

    start = int(raw_input("Start emulation at address:"), 16)
    end = int(raw_input("End emulation at address:"), 16)

    #mu.hook_add(unicorn.UC_HOOK_CODE, hook_code, None, elf.elfHdr.e_entry.value,
    #            elf.elfHdr.e_entry.value + 40)
    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code, None, start, end)

    logger.info("Emulating")
    #mu.emu_start(elf.elfHdr.e_entry.value, elf.elfHdr.e_entry.value + 40)
    mu.emu_start(start, end)

    logger.info("Dump of registers can be found at ./dump_regs")
    logger.info("Dump of memory mappings can be found at ./dump_mappings")
    logger.info("Finished")

if __name__ == "__main__":
    main()
