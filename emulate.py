import pylibelf
import unicorn
import elfconstants
import logging
import unicorn.x86_const
import argparse
import utils

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

def hook_code(mu, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    utils.dump_regs(mu, address, size)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Name of file to be emulated")
    parser.add_argument("-log", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Preffered logging level")
    args = parser.parse_args()
    logging.basicConfig(level=logging_level(args.log))
    logger = logging.getLogger(__name__)
    
    logger.info("Started")
    elf = pylibelf.ELF(args.filename)
    open('dump_regs', 'w').close()
    open('dump_mappings', 'w').close()
    logger.debug("Entry Point: " + str(hex(elf.elfHdr.e_entry.value))) 
    
    addr, offset, memsz, filesz, vaddr, rnd_addr, rnd_size = [[] for _ in xrange(7)]

    logger.info("Retrieving the program headers")
    for phdr in elf.PhdrTable:
        for _, segment_value in elfconstants.elf_segment_types:
            if phdr.p_type.value == segment_value:
                logger.debug(_ + ":" + str(hex(phdr.p_paddr.value)) + ":" +str(hex(phdr.p_memsz.value)))
                addr.append(phdr.p_paddr.value)
                vaddr.append(phdr.p_vaddr.value)
                memsz.append(phdr.p_memsz.value)
                filesz.append(phdr.p_filesz.value)
                offset.append(phdr.p_offset.value)
    
    roundoff_addr = lambda val: val if val % 4096 == 0 else ((val/4096)*4096)
    roundoff = lambda val: val if val % 4096 == 0 else ((val/4096)*4096 + 4096 + 4096)
    
    logger.info("Rounding off the Vaddr and Memsz and consolidating mappings")
    rnd_addr.append(roundoff_addr(vaddr[0]))
    rnd_size.append(roundoff(memsz[0]))
    tmp = 0
    
    for i in xrange(1, len(vaddr)):
        tmp_addr = roundoff_addr(vaddr[i])
        tmp_sz = roundoff(memsz[i])
        flag = 0
        for j in xrange(len(rnd_addr)):
            if rnd_addr[j] == tmp_addr:
                flag = 1
                if vaddr[i] + memsz[i] > rnd_addr[j] + rnd_size[j]:
                    tmp_sz = roundoff((tmp_addr + memsz[i]) - (rnd_addr[j] + rnd_size[j])) 
                    rnd_size[j] += tmp_sz
                break
        if flag == 0:
            rnd_addr.append(tmp_addr)
            rnd_size.append(tmp_sz)

    logger.info("Memory mapping")
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    try:
        for i in xrange(len(rnd_addr)):
            mu.mem_map(rnd_addr[i], rnd_size[i])
            logger.debug(hex(rnd_addr[i]) + ":" + hex(rnd_size[i]))
        mu.mem_map(0x00007ffffffde000 , 0x21000)
    except unicorn.unicorn.UcError:
        logger.error("Invalid argument (UC_ERR_ARG)")
        exit(0)

    logger.info("Writing into the memory mapped area at their respective offsets")
    for i in xrange(len(offset)):
        data = elf.readDataAtOffset(offset[i], memsz[i])
        logger.debug(hex(vaddr[i]))
        mu.mem_write(vaddr[i], data)
        utils.dump_mapping(mu, vaddr[i], memsz[i])

    logger.info("Retrieving the differnt sections and also writing into memory")
    for sec in elf.ShdrTable:
        logger.debug(sec.sectionName + ":" + str(hex(sec.sh_addr.value)) + ":" + str(hex(sec.sh_size.value)))
        if sec.sh_addr.value == 0x0:
            continue
        data = elf.readDataAtOffset(sec.sh_offset.value, sec.sh_size.value)
        mu.mem_write(sec.sh_addr.value, data)

    mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, 0x7fffffffb000)

    utils.dump_at_addr(mu, 0x400ce0, 0x10)

    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code, None, elf.elfHdr.e_entry.value, elf.elfHdr.e_entry.value + 40)
    
    logger.info("Emulating")
    mu.emu_start(elf.elfHdr.e_entry.value, elf.elfHdr.e_entry.value + 40)
    
    logger.info("Finished")

if __name__ == "__main__":
    main()
