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
    time.sleep(1)


#method used to read a 32 bit value from a specific address using open ocd
def read32(address,p):
    command='mdw phys '+int_t0_string_hex(address)+ ' 1'
    print(command)
    p.sendline(command)
    result=p.recvuntil(b'\r>')
    result=result[38:-5]
    result_str ="0x"+ result.decode('utf-8')
    num=int(result_str,16)
    time.sleep(1)
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
    time.sleep(1)
    #Wait until the execution is finished
    reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    time.sleep(1)
    # print(reg)
    # while (reg & ITE) != ITE:
    #     reg=read32(DEBUG_REGISTER_ADDR+EDSCR_OFFSET,p)
    #     print(hex(reg & ITE) + " " + hex(ITE))
    #     time.sleep(1)
    # time.sleep(1)
    # if((reg & ERR) == ERR):
    #     print("Error in execution")
    #     return -1
    # time.sleep(1)

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



#defininf a function to send this command to openocd
#        mcr cpnum op1 CRn CRm op2 value
#        mcr p14, 0, R0, c0, c5, 0
def mcr(cpnum,op1,CRn,CRm,op2, value,p):
    command='aarch64 mcr '+str(cpnum)+' '+str(op1)+'  '+str(CRn)+' '+str(CRm)+' '+str(op2)+' '+str(value)
    p.sendline(command)
    p.recvuntil(b'\r>')

#degininf a function to read this command from openocd
#        mrc p15, 3, R0, c4, c5, 1
def mrc(cpnum,coproc,op1,CRn,CRm,op2,p):
    command='aarch64 mrc '+str(cpnum)+' '+str(coproc)+' '+str(op1)+'  '+str(CRn)+' '+str(CRm)+' '+str(op2)
    p.sendline(command)
    p.recvuntil(b'\r>')


def save_register(cpnum,coproc,op1,CRn,CRm,op2, p):
    mrc(cpnum ,coproc,op1, CRn, CRm, op2, p)
    input("save register wait")
    time.sleep(1)
    mcr(14, 0, 0, 0, 5, 0, p)
    input("save register wait")
    time.sleep(1)
    ret=read32(DEBUG_REGISTER_ADDR + DBGDTRTX_OFFSET,p)
    input("save register wait")
    return ret

#the following command can be useful to do the first step of the attack,
#it clear the os lock and enable the crosstrigger intergace
# Command: aarch64 dbginit


def read_src(p):
    #the main idea is to use aarch64 and halt to resume the first 4 step of the attack
    #see documentation of open ocd for more detail
    #
    #see
    pass
