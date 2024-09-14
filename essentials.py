
from capstone import *
from keystone import *
import random

mathInstructions = ["xor", "add", "sub", "mov"]

jumpInstructions = ["jmp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "call", "loop", "loope", "loopne", "loopnz", "loopz"]#Add other instructions and move to main

critical_instrs = ["jmp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "call", "loop", "loope", "loopne", "loopnz", "loopz", "int", "syscall", "call", "pusha", "popa", "cdq", "cwd", "div", "idiv", "lods", "lodsd", "lodsb", "ret", "retn", "retq"]#Basically register dependednt instructions or stuff that alters the control flow

badChars = ["00","04","05","09","0A","0a","20"]

floating_point = ["fldpi", "fldl2e"]

x86_32_registers = ["eax", "ecx", "edx", "ebx"]
full_x86_regs = ["eax", "ecx", "edx", "ebx", "edi", "esi"]

print_s = lambda code,msg : print(f"\x1b[{code}m{msg}\x1b[0m")

def gen_random_register():
    return full_x86_regs[random.randint(0, len(full_x86_regs)-1)]

def bytesToString(byteArray:bytes) -> str:
    string = "".join("\\x{:02x}".format(b) for b in byteArray)
    return string


def unsplit_string(split_list:list[str], split_by:str) -> str:
    returnable = ""
    for i, split in enumerate(split_list):
        if i>=1:
            returnable+=split_by+split
        else:
            returnable+=split
    return returnable

def findall_regular(string:str, phrase:str) -> list:
    returnable = []
    findIndex = 0
    while True:
        loc = string.find(phrase, findIndex)
        if loc<=0:
            break
        else:
            returnable.append(loc)
            findIndex += loc+len(phrase)
    return returnable

#Under construction
def print_x(msg, **inserting) -> None:
    to_change_count = msg.count("{}")
    print(findall_regular(msg, "{}"))
    if len(inserting)!=to_change_count:
        return
    print(inserting.items())
    #msg = msg.format(for i, in enumerate(inserting))
    print(msg)

def debughook_verbose(func):
    def wrapper(*args, **kwargs):
        name = func.__name__
        print_s("96",f"Debug: calling {name} with parameters: {args} and keywords: {kwargs}")
        returnable = func(*args, **kwargs)
        if(returnable is None):
            print_s("96",f"Debug: {name} was called")
        else:
            print_s("96",f"Debug: {name} was called and returned {returnable} with type {type(returnable)}")
        return returnable
    return wrapper

def debughook(func):
    def wrapper(*args, **kwargs):
        name = func.__name__
        print_s("96",f"Debug: calling {name}")
        returnable = func(*args, **kwargs)
        if(returnable is None):
            print_s("96",f"Debug: {name} was called")
        else:
            print_s("96",f"Debug: {name} was called and returned {returnable} with type {type(returnable)}")
        return returnable
    return wrapper

def debughookend(func):
    def wrapper(*args, **kwargs):
        returnable = func(*args, **kwargs)
        name = func.__name__
        if(returnable is None):
            print_s("96",f"Debug: {name} was called")
        else:
            print_s("96",f"Debug: {name} was called and returned {returnable} with type {type(returnable)}")
        return returnable
    return wrapper

def debughookbefore(func):
    def wrapper(*args, **kwargs):
        name = func.__name__
        print_s("96",f"Debug: calling {name}")
        returnable = func(*args, **kwargs)
        return returnable
    return wrapper

def breakafter(func):
    def wrapper(*args, **kwargs):
        returnable = func(*args, **kwargs)
        name = func.__name__
        if(returnable is None):
            print_s("96",f"Debug: {name} was called")
        else:
            print_s("96",f"Debug: {name} was called and returned {returnable} with type {type(returnable)}")
        breakpoint()
        return returnable
    return wrapper

def breakbefore(func):
    def wrapper(*args, **kwargs):
        name = func.__name__
        print_s("96",f"Debug: calling {name}")
        breakpoint()
        returnable = func(*args, **kwargs)
        return returnable
    return wrapper

def realtime_update(self, func): #I didn't know you could do this
    def wrapper(*args, **kwargs):
        returnable = func(*args, **kwargs)
        self.refresh_jumps()
        return returnable
    return wrapper

def add_to_int_list(lst:list[int], new_ind:int, new_item:int):
    for i, item in enumerate(lst):
        if new_item<=item:
            lst[i]+=1
    lst.insert(new_ind, new_item)

#Returns an index of the first use
#@debughook
def find_first_register_use(instructions:list, register:str, startIndex = None) -> int:
    if startIndex==None:
        startIndex = 0
    returnable = -1
    for index, instruction in enumerate(instructions[startIndex:], start=startIndex):
        if(instruction.find(register)>-1):
            returnable = index
            break
    return returnable

def find_first_register_uses(instructions:list[str], registers:list[str], startIndex = None) -> list[int]:
    if startIndex==None:
        startIndex = 0
    returnable = [-1, -1, -1, -1]
    for reg_ind, register in enumerate(registers): #What about subregisters
        for subreg_ind, subregister in enumerate(registerClassMain(register)):
            found_yet:bool = False
            for index, instruction in enumerate(instructions[startIndex:], start=startIndex):
                if(instruction.find(subregister)>-1):
                    returnable[reg_ind] = index
                    found_yet = True
                    break
            if found_yet:
                break
    return returnable

#Put the new instruction after the jump or target if it is register dependent, make the end index within the same subroutine
#update to be in same subroutine
#When something is dereferenced, all hell breaks loose
#@debughook_verbose
#If there is an issue with xor byte ptr...

def get_register_size(instruction:str) -> int:
#    if(instruction.split(',')[0]=="xor byte"):
    #Get the words of the function first:
    for i in instruction.split(" "):
        match i.lower():
            case "byte":
                return 8
            case "word":
                return 16
            case "dword":
                return 32
            case "qword":
                return 64
    try:
        if not instruction.split(" ")[1]:
            return 0
        for i in range(len(instruction.split(" "))):
            if len(instruction.split(" ")[1])<2:
                #print("NOT 1")
                return 0
    except IndexError:
        #print("NOT 2")
        return 0
    if instruction.split(" ")[1][0]=='r':
        return 64
    elif instruction.split(" ")[1][0]=='e':
        return 32
    elif instruction.split(" ")[1][1]=='x':
        return 16
    elif instruction.split(" ")[1][1]=='h':
        return 8
    elif instruction.split(" ")[1][1]=='l':
        return 8
    else:

        if len(instruction.split("["))==1:
            #print("None")
            return 0
        else:
            if instruction.split("[")[1][0]=='r':
                return 64
            elif instruction.split("[")[1][0]=='e':
                return 32
            elif instruction.split("[")[1][1]=='x':
                return 16
            elif instruction.split("[")[1][1]=='h':
                return 8
            elif instruction.split("[")[1][1]=='l':
                return 8
            else:
                return 0
        return 0
#print(get_register_size("mov word ptr [esp + 0x3c], 0x101"))

def registerClassMain(base:str) -> list:
    returnable = []
    group = mapRegisterToNumber(base)
    groupTen = int(group/10)*10
    for i in range(5):
        returnable.append(mapNumberToRegister(groupTen+i))
    return returnable

#@debughook
def target_in_scope(instructions:list, start_ind:int) -> bool:
    try:
        target = instructions[start_ind].split(" ")[1]
        if target!="0x":
            return False
    except IndexError:
        return False



def contains_bad_chars(byteArray:str) -> bool:
    for i in badChars:
        for j in range(0,len(byteArray), 2):
            if (j+2<=len(byteArray)) and (byteArray[j:j+2]==i):
                return True
    return False

def beautify_hex(hex_original:str, arch:int) -> str:
    #print(hex_original)
    num_digits = len(hex_original)-2
    x_loc = hex_original.find('x')
    #print(x_loc)
    for i in range(arch//4-num_digits):
        hex_original = hex_original[:x_loc+1] + '0' + hex_original[x_loc+1:]
    return hex_original

def unbeautify_hex(hex_original:str) -> str: # 
    exclusivity_index = 2
    try:
        for i, num in enumerate(hex_original[2:],start=2): #needs ti increase by 2
            if i%2!=0:
                continue
            if i+2<=len(hex_original)-2:
                if num+hex_original[i+1]!='00':
                    return "0x"+hex_original[exclusivity_index:]
                    break
                else:
                    exclusivity_index+=2

    except IndexError:
        print("Index Error from unbeautify_hex")
        return "0x"+hex_original[exclusivity_index:]

#@debughook_verbose
def random_hex(arch:int) -> str:
    if arch%4==0:
        length_of_hex = int(arch/4)
        string = "0x"
        while(string == "0x"):
            #print("RANDOM_HEX")
            for i in range(length_of_hex):
                string += (random.choice("0123456789abcdef"))
            if not contains_bad_chars(string):
                return string
            string = "0x"
    return "0xdeadbeef"

#def random_hex_xor_pair(original:str) -> list: #reverse it too
#    product = ""
#    verified_no_xor:bool = False
#    while not(verified_no_xor): #verify the product has no badchars:
#        hex1 = beautify_hex(random_hex((len(original)-2)*4))
#        #print(hex1)
#        product = hex(int(original[2:], 16)^int(hex1[2:], 16))
#        if not contains_bad_chars(product):
#            return [hex1, product]
#    return [original, "0x00000000"]

#@debughook_verbose
def random_hex_xor_pair(original:str, arch:int) -> list: #reverse it too
    product = ""
    verified_no_xor:bool = False
    original = beautify_hex(original, arch)
    while not(verified_no_xor): #verify the product has no badchars:
        hex1 = beautify_hex(random_hex(arch), arch) #Random hex is breaking because arch is hard to find fo 0x101
        #print(hex1)
        #breakpoint()
        product = beautify_hex(hex(int(original[2:], 16)^int(hex1[2:], 16)), arch)
        if not contains_bad_chars(product):
            return [hex1, product]
    return [original, "0x00000000"]

#@debughook_verbose
def random_hex_add_pair(original:str, arch:int) -> list: #reverse it too
    product = ""
    verified_no_xor:bool = False
    original = beautify_hex(original, arch) #Have an exception handler in here
    #beautify_hex breaks
    while not(verified_no_xor): #verify the product has no badchars:
        #print("WHILE CALL")
        #verify that if added with the original, it will not go above int("0x"+"f"*arch/4, 16)
        hex1 = beautify_hex(random_hex(arch), arch)
        #print(hex1)
        #print(int(hex1,16)>=int(original,16))
        #print(len(hex1)!=arch/4+2)
        #breakpoint()
        #Breaks when 0xffffffff, breaks when 
        if int(hex1,16)<=int(original,16) or len(hex1)!=arch/4+2: #True False
            print(hex1)
            print(original)
            print(int(hex1,16))
            print(int(original,16))
            print(int(hex1,16)<=int(original,16))
            print(len(hex1))
            print(arch/4+2)
            print(len(hex1)!=arch/4+2)
            print("Add branch 1")
            continue
        product = beautify_hex(hex(int(original[2:], 16)-int(hex1[2:], 16)), arch)

       # print(hex1)
       # print(product)

        if (int(hex1,16)+int(product, 16)>=int("0x"+"f"*int(arch/4), 16)):
            print("Add branch 2")
            continue
        if not contains_bad_chars(product) and len(product)==len(hex1):
            verified_no_xor = True
            return [hex1, product]
        #print("Jumping Back")
    return [original, "0x00000000"]

#IMPORTANT: MAKE SURE THAT WHEN SOMETHING IS BEING ADDED, IT IS WITH ADD, RIGHT NOW IT IS DOING SUB
#@debughook_verbose
def random_hex_sub_pair(original:str, arch:int) -> list: #reverse it too
    product = ""
    verified_no_xor:bool = False
    original = beautify_hex(original, arch) #Have an exception handler in here
    while not(verified_no_xor): #verify the product has no badchars:
        hex1 = beautify_hex(random_hex(arch), arch)
        if int(hex1,16)<=int(original,16) or len(hex1)!=arch/4+2:
            print("Sub branch 1")
            print(hex1)
            print(original)
            continue
        product = beautify_hex(hex(int(hex1[2:], 16)-int(original[2:], 16)), arch)
        if (int(hex1,16)-int(product, 16)<0):
            print("Sub branch 2")
            continue
        if not contains_bad_chars(product) and len(product)==len(hex1):
            return [hex1, product]
    print("Returning bad")
    return [original, "0x00000000"]

def random_hex_xor_string(arch:int) -> None: #reverse it too
    good_xor = False
    while good_xor is False:
        hex1 = random_hex(arch)
        hex2 = random_hex(arch)
        returnable = hex(int(hex1, 16) ^ int(hex2, 16))
        if not contains_bad_chars(hex(int(hex1, 16) ^ int(hex2, 16))):
            return returnable
    return "0xdeadbeef"

def mapRegisterToNumber(register) -> int:
    match(register):
        case "rax": #64-bit compatibility later
            return 10
        case "eax":
            return 11
        case "ax":
            return 12
        case "al": 
            return 13
        case "ah":
            return 14
        case "rcx":
            return 20
        case "ecx":
            return 21
        case "cx":
            return 22
        case "cl":
            return 23
        case "ch":
            return 24
        case "rdx":
            return 30
        case "edx":
            return 31
        case "dx":
            return 32
        case "dl":
            return 33
        case "dh":
            return 34
        case "rbx":
            return 40
        case "ebx":
            return 41
        case "bx":
            return 42
        case "bl":
            return 43
        case "bh":
            return 44
        case "rsp":
            return 50
        case "esp":
            return 51
        case "sp":
            return 52
        case "rbp":
            return 60
        case "ebp":
            return 61
        case "bp":
            return 62
        case "rsi":
            return 70
        case "esi":
            return 71
        case "si":
            return 72
        case "rdi":
            return 80
        case "edi":
            return 81
        case "di":
            return 82
        case _:
            return 0

def mapNumberToRegister(registerNum) -> str:
    match(registerNum):
        case 10: #64-bit compatibility later
            return "rax"
        case 11:
            return "eax"
        case 12:
            return "ax"
        case 13: 
            return "al"
        case 14:
            return "ah"
        case 20:
            return "rcx"
        case 21:
            return "ecx"
        case 22:
            return "cx"
        case 23:
            return "cl"
        case 24:
            return "ch"
        case 30:
            return "rdx"
        case 31:
            return "edx"
        case 32:
            return "dx"
        case 33:
            return "dl"
        case 34:
            return "dh"
        case 40:
            return "rbx"
        case 41:
            return "ebx"
        case 42:
            return "bx"
        case 43:
            return "bl"
        case 44:
            return "bh"
        case 50:
            return "rsp"
        case 51:
            return "esp"
        case 52:
            return "sp"
        case 60:
            return "rbp"
        case 61:
            return "ebp"
        case 62:
            return "bp"
        case 70:
            return "rsi"
        case 71:
            return "esi"
        case 72:
            return "si"
        case 80:
            return "rdi"
        case 81:
            return "edi"
        case 82:
            return "di"
        case _:
            return "0"

#@debughook
def find_registers_between(instructions:list, start_ind:int, end:int, *register_letters) -> list: #Takes args just in case I need to use them when not in a list
    returnables = [-1]*len(register_letters)
    for index, instruction in enumerate(instructions[start_ind:end], start=start_ind):
        for reg_ind, register in enumerate(register_letters):
            for subreg in registerClassMain(register):
                if(instruction.find(subreg)>-1) and returnables[reg_ind]==-1:
                    returnables[reg_ind] = index
    return returnables

@debughook_verbose
def find_registers_between_list(instructions:list, start_ind:int, end:int, register_letters:list) -> list: #Takes args just in case I need to use them when not in a list
    returnables = [-1]*len(register_letters)
    for index, instruction in enumerate(instructions[start_ind:end], start=start_ind):
        for reg_ind, register in enumerate(register_letters):
            for subreg in registerClassMain(register):
                if(instruction.find(subreg)>-1) and returnables[reg_ind]==-1:
                    returnables[reg_ind] = index
    return returnables

jumpSnapshots = []

debugJumpTargets = []

def removeExtraSlashBytes(original:str) -> bytes:
    original = original.replace("\n", "")
    original = original.replace("x","")
    string:bytes = bytes.fromhex(original.replace("\\", ''))
    return string

def changeChar(string, index, toReplace):
    return string[0:index]+toReplace+string[index + len(toReplace):]


def replace(string, index, new, contIndex)-> str:
    return string[0:index]+new+string[contIndex:]

REGISTERS= ["eax", "ecx", "edx", "ebx"]#Add compatibility for storing more registers andreturn registers if needed for loop and ret instructions

REGISTERS_64 = ["rax", "rcx", "rdx", "rbx"]#Add compatibility for storing more registers andreturn registers if needed for loop and ret instructions

class Shellcode:
    def __init__(self, shellcode:bytes, is_x64:bool):
        self.shellcode:bytes = shellcode#Convert to string
        self.jumpSnapshots:list = []
        self.jumpIndexes:list = []
        self.jumpTargets:list = []
        self.takenRegisters:list = []
        self.takenRegisters:list = []
        self.is_64 = is_x64
        self.jumpAddition = []
        self.instructions = []
        self.arch = (CS_ARCH_X86, KS_ARCH_X86) #Preparing for a complete rewrite
        self.mode = None #

    def __init__(self, shellcode:str, is_x64:bool):
        self.shellcode:bytes = removeExtraSlashBytes(shellcode)
        self.jumpSnapshots:list = []
        self.jumpIndexes:list = []
        self.jumpTargets:list = []
        self.takenRegisters:list = []
        self.takenRegisters:list = []
        self.is_64:bool = is_x64
        self.jumpAddition = []
        self.instructions = []
    
    def getCode(self):#Just in case it becomes private
        return self.shellcode

    def is_64_bit(self):
        return self.is_64

    @property
    def assembled_instrs(self):
        if self.is_64:
            return Shellcode.assemble64(self.shellcode)
        return Shellcode.assemble(self.shellcode)

    @property
    def length(self):
        return len(self.shellcode)

    @property
    def string(self):
        return bytesToString(self.shellcode)

    def get_subroutines(self, instructions:list) -> [list, list]:
        assembly_offset:int = 0
        self.jump_split_by_index:list[int] = []
        self.jump_split_by_offset:list[int] = []
        for index, instr in enumerate(instructions):
            assembly_offset+=(len(Shellcode.assemble64([instr])) if self.is_64 else len(Shellcode.assemble([instr])))
            for jump_instr in jumpInstructions:
                if jump_instr in instr:
                    self.jump_split_by_index.append(index)
                    self.jump_split_by_offset.append(assembly_offset)
                    break

    def registers_in_subroutine(self, instructions):
        found_routine_inds = []
        #print(self.jump_split_by_index)
        for ind, sub_start in enumerate(self.jump_split_by_index[:-1]):
            found_registers = []
            for reg_ind, reg in enumerate(REGISTERS):
                reg_found = False
                for subreg in registerClassMain(reg):
                    for instruction in instructions[sub_start:self.jump_split_by_index[ind+1]]: 
                        if subreg in instruction:
                            reg_found = True
                if reg_found:
                    #print(REGISTERS)
                    #print(ind)
                    #print(sub_start)
                    found_registers.append(REGISTERS_64[reg_ind] if self.is_64 else REGISTERS[reg_ind])
            if len(found_registers)==4:
                found_routine_inds.append([sub_start, self.jump_split_by_index[ind+1]])
        return found_routine_inds

    def jump_out_of_subroutine(self, instructions, start_ind, end_ind): #Is the jump going out of the subroutine
        start_offset = Shellcode.index_to_offset(self.is_64, instructions, start_ind)#One to the sta
        end_offset = Shellcode.index_to_offset(self.is_64, instructions, end_ind)#One to the start

        jumps_out_of_subroutine = []

        for jump_ind, jump_instr in enumerate(self.jumpIndexes):
            if jump_ind>=start_ind and jump_ind<=end_ind:
                if '-0x' in jump_instr: #Jumps are relative: If jump to offset+len - start>jump_negative
                    if(int(Shellcode.index_to_offset(self.is_64, instructions, jump_ind)+len(Shellcode.assemble64([jump_instr]) if self.is_64 else Shellcode.assemble([jump_instr]))-Shellcode.index_to_offset(self.is_64, instructions, start_ind)),16)<int(jump_instr.split(" ")[1], 16):
                        jumps_out_of_subroutine.append(jump_ind)

                elif '0x' in jump_instr: #Jumps are relative: If jump to offset+len - start>jump_negative
                    if(int(Shellcode.index_to_offset(self.is_64, instructions, end_ind) - Shellcode.index_to_offset(self.is_64, instructions, jump_ind)+len(Shellcode.assemble64([jump_instr]) if self.is_64 else Shellcode.assemble([jump_instr]))),16)>int(jump_instr.split(" ")[1], 16):
                        jumps_out_of_subroutine.append(jump_ind)
        return jumps_out_of_subroutine

    def jump_in_to_subroutine(self, instructions, start_ind, end_ind):
        start_offset = Shellcode.index_to_offset(self.is_64, instructions, start_ind)#One to the sta
        end_offset = Shellcode.index_to_offset(self.is_64, instructions, end_ind)#One to the start

        jumps_in_to_subroutine = []

        for jump_ind, jump_instr in enumerate(self.jumpIndexes):
            if jump_ind<start_ind and jump_ind>end_ind:
                if '-0x' in jump_instr: 
                    jump_to = Shellcode.index_to_offset(jump_ind)+len(Shellcode.assemble64(jump_ind) if self.is_64 else Shellcode.assemble(jump_ind))-int(jump_instr.split(" ")[1][1:],16)
                    if jump_to>=start_ind and jump_to<=end_ind:
                        jumps_in_to_subroutine.append(jump_ind)
                elif '0x' in jump_instr: 
                    jump_to = Shellcode.index_to_offset(jump_ind)+len(Shellcode.assemble64(jump_ind) if self.is_64 else Shellcode.assemble(jump_ind))+int(jump_instr.split(" ")[1][1:],16)
                    if jump_to>=start_ind and jump_to<=end_ind:
                        jumps_in_to_subroutine.append(jump_ind)
        return jumps_in_to_subroutine



    @staticmethod
    def index_to_offset(is_64:bool, instructions, index):
        offset = 0x0
        for i, instr in enumerate(instructions):
            if index==i:
                break
            offset+=len(Shellcode.assemble64([instr]) if is_64 else Shellcode.assemble([instr]))
        return offset


    @staticmethod
    def offset_to_index(is_64:bool, instructions, offset):
        offset = 0x0
        returnable = 0
        for i, instr in instructions:
            if index==i:
                returnable = i
                break
            offset+=len(Shellcode.assemble64(instr) if is_64 else Shellcode.assemble(instr))
        return offset

    #def check_jump_in_subroutine(self, subroutine_ind):
    #    self.jump_split_by_index.

    def update_bounds_of_reg_swap(self, instructions:list[str], before:int,after:int = None) -> list[int]:
        #Check if before is in a jump
        #If so, check after to make sure it is in the subroutine, if not make it somewhere in the same subroutine
        if after is None:
            after = len(instructions)
        returnable = [before, after]
        for i, jump_ind in enumerate(self.jumpIndexes):
            #remember to add this with after as well, but not now

            #if a forward jump: if before is less than the target and after > target and before>jump, after will be moved within
            if jump_ind<self.jumpTargets[i] and before<self.jumpTargets[i] and before>jump_ind and after>self.jumpTargets[i]:
                returnable[1] = self.jumpTargets[i]-1
            #If backward: if before < jump and after>jump and before>target
            elif jump_ind>self.jumpTargets[i] and before<jump_ind and after>jump_ind and before>self.jumpTargets[i]:
                returnable[1] = jump_ind-1
        return returnable


    #@debughook_verbose
    def is_jump_in_sc(self, index, instructions) -> bool:
        jump_number = int(instructions[index].split(" ")[1], 16)
        rest_of_instrs = 0
        if jump_number >= 0:
            if self.is_64:
                rest_of_instrs+=len(Shellcode.assemble64(instructions[index+1:]))
            else:
                rest_of_instrs+=len(Shellcode.assemble(instructions[index+1:]))
            if jump_number>=rest_of_instrs:
                return False
        else:
            if self.is_64:
                rest_of_instrs-=len(Shellcode.assemble64(instructions[0:index+1]))
            else:
                rest_of_instrs-=len(Shellcode.assemble(instructions[0:index+1]))
            if jump_number<rest_of_instrs:
                return False
        #print(f"Returning within scope: {instructions[index]}")
        return True

    #@debughook_verbose
    def is_jump_in_sc_abs(self, index, instructions) -> bool:
        jump_number = int(instructions[index].split(" ")[1], 16)
        rest_of_instrs = 0
        if self.is_64:
            rest_of_instrs+=len(Shellcode.assemble64(instructions))
        else:
            rest_of_instrs+=len(Shellcode.assemble(instructions))
        return False if jump_number>rest_of_instrs else True

   # def dec_jump(self, instructions, index):
   #     instructions[index] = instructions[index].split(" ")[0] + " " + hex(int(instructions[index].split(" ")[1], 16)-1)

    def set_jump(self, instructions, index, new_val) -> None:
        instructions[index] = instructions[index].split(" ")[0] + " " + hex(new_val+2) #Keystone is stupid when it comes to this stuff, so I have to add the lenfth of the jump
    
    #@debughook_verbose
    #Keystone is subtracting 2 from the jump when assembling
    def add_jump(self, instructions, new_index, new_target_ind, variant:str = "jmp", shift_jump:bool = True): #Eventually, when stated, it will append the target if it matches the new index
        #print(new_target_ind)
        #print(instructions[new_target_ind])
        #go through jump indexes, if it is more that a certain index, insert before just to keep it in order
        #Then insert a new jump instruction accounting for everything between 
        #If forward start with i+1 to target
        #If backward start with i back to target
        jump_list_insert_index:int = 0
        for index, instr in enumerate(self.jumpIndexes):
            if new_index<instr:
                jump_list_insert_index=index
                break
        self.jumpIndexes.insert(jump_list_insert_index, new_index)
        self.jumpTargets.insert(jump_list_insert_index, new_target_ind)
        
        add_to_jump = 0x0
        instruction_count = 0
        if(new_index<new_target_ind):
            if self.is_64:
                add_to_jump=len(Shellcode.assemble64([f"{variant} {hex(add_to_jump)}"]))
                for i, instruction in enumerate(instructions[new_index:new_target_ind]):
                    add_to_jump+=len(Shellcode.assemble64([instruction]))
                    instruction_count+=1
            else:
                add_to_jump=len(Shellcode.assemble([f"{variant} {hex(add_to_jump)}"]))
                for i, instruction in enumerate(instructions[new_index:new_target_ind]):
                    add_to_jump+=len(Shellcode.assemble([instruction]))
                    instruction_count+=1
        elif(new_index>new_target_ind):
            if self.is_64:
                for i, instruction in enumerate(instructions[new_target_ind:new_index]):
                    add_to_jump-=len(Shellcode.assemble64([instruction]))
                    instruction_count+=1
            else:
                for i, instruction in enumerate(instructions[new_target_ind:new_index]):
                    add_to_jump-=len(Shellcode.assemble([instruction]))
                    #print(f"Added: {len(Shellcode.assemble64([instruction]))}")
                    instruction_count+=1

        #If the index is a jump target, update the length to skip the jump
        b4 = len(self.jumpTargets)
        #print(instructions)
        #print(f"New Index: {new_index}")
        self.insertWithCare(instructions, f"{variant} {hex(add_to_jump)}", new_index, False, True, True, shift_jump) #This screws it up, add option to not add it
        for ind_in_targets, target in enumerate(self.jumpTargets):
            if(new_index==target):
                if self.is_64:
                    if int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)<0:
                        instructions[self.jumpIndexes[ind_in_targets]] = instructions[self.jumpIndexes[ind_in_targets]].split(" ")[0]+ " " +hex(int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)+len(Shellcode.assemble64([f"{variant} {hex(add_to_jump)}"])))
                    else:
                        instructions[self.jumpIndexes[ind_in_targets]] = instructions[self.jumpIndexes[ind_in_targets]].split(" ")[0]+ " " +hex(int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)+len(Shellcode.assemble64([f"{variant} {hex(add_to_jump)}"])))
                else:
                    if int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)<0:
                        instructions[self.jumpIndexes[ind_in_targets]] = instructions[self.jumpIndexes[ind_in_targets]].split(" ")[0]+ " " +hex(int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)+len(Shellcode.assemble([f"{variant} {hex(add_to_jump)}"])))
                    else:
                        instructions[self.jumpIndexes[ind_in_targets]] = instructions[self.jumpIndexes[ind_in_targets]].split(" ")[0]+ " " +hex(int(instructions[self.jumpIndexes[ind_in_targets]].split(" ")[1],16)+len(Shellcode.assemble([f"{variant} {hex(add_to_jump)}"])))
        #print(instructions)
        
    #   FIX THE INSERT WITH CARE THING, IT IS THROWING THE LOOP OFF!!!
        #Maybe try it before?
        
        #Temporary
        self.jumpIndexes[jump_list_insert_index]-=1

    @staticmethod
    def assemble_between(instructions, start_ind, end_ind, is_64:bool) -> int:
        length = 0
        for i, instruction in enumerate(instructions[start_ind:end_ind], start=start_ind):
            length += len(Shellcode.assemble64([instruction]) if is_64 else Shellcode.assemble([instruction]))
        return length
    

    @staticmethod
    def assemble_to_target(instructions, start_ind, end_bytes, is_64:bool) -> int:
        #print(end_bytes)
        length = 0
        index = 0
        for i, instruction in enumerate(instructions[start_ind:], start=start_ind):
            #print(instruction)
            #print(length)
            #print(hex(length))
            length += len(Shellcode.assemble64([instruction]) if is_64 else Shellcode.assemble([instruction]))
            if length==end_bytes:
                index = i
                break
        return index


    def fixJumpErrors(self, instructions:list, code:bytes) -> list:
        for i, current_instr in enumerate(instructions): #IDEA: for each jump instruction, 
            #print(jumpInstructions)
            #breakpoint()
            for j, jumpInstruction in enumerate(jumpInstructions): 
                if((targetInstruction:=current_instr.find(jumpInstruction+" 0x"))==0 and "loop" not in current_instr):
                    offset = int(instructions[i].split(" ")[1],16)-0x1000
                    instructions[i] = instructions[i].split(" ")[0]+" "+str(hex(offset))

                elif((targetInstruction:=current_instr.find(jumpInstruction+" 0x"))==0 and "loop" in current_instr):
                    offset = (int(Shellcode.disassemble_loop(code, i)[-1])-254 if self.is_64 else int(Shellcode.disassemble_loop(code, i)[-1])-254) #Does not account for forward loops
                    instructions[i] = instructions[i].split(" ")[0]+" "+str(hex(offset))

        return instructions

    def findJump(self, instructions:list) -> list: #for some reason it is duping instructions, jle is counted as jl
        #print(f"Instructions length: {len(instructions)}")
        #print(f"Instructions length: {len(Shellcode.assemble(instructions))}")
        returnable = []
        counter = 0
        for i, instruction in enumerate(instructions):
            for jumpInstruction in jumpInstructions:
                if(loc :=(instruction.find(jumpInstruction))==0) and instruction[instruction.find(jumpInstruction)+len(jumpInstruction)]==" ":# and instruction[loc+len(jumpInstruction)]==" ":
                    counter+=1
                    #print(instruction)

                    if len(instruction.split(" ")[1])>=3:
                        if instruction.split(" ")[1][0:3]=="-0x" and self.is_jump_in_sc_abs(i, instructions):
                            returnable.append(i)
                        elif instruction.split(" ")[1][0:2]=="0x" and self.is_jump_in_sc_abs(i, instructions):
                            returnable.append(i)
        self.jumpIndexes = returnable
        #print(f"Jump Count: {counter}") #Should be 5 call + 37 j
        return returnable
    
    def findJumpTargets(self, code:bytes) -> list:
        instructions = Shellcode.disassemble(code)
        indexArray = []
        targetIndexArray = []
        for i in range(len(instructions)): #IDEA: for each jump instruction, 
            for jumpInstruction in self.jumpInstructions: 
                if((targetInstruction:=instructions[i].find(jumpInstruction))>-1):

                    offset = int(instructions[i].split(" ")[1],16)-0x1000
                    instructions[i] = instructions[i].split(" ")[0]+" "+str(hex(offset))
                    indexArray.append(targetInstruction)
                    if self.is_64:
                        landingInstruction = Shellcode.disassemble64(Shellcode.assemble64(instructions)[offset:])[0] 
                    else:
                        landingInstruction = Shellcode.disassemble(Shellcode.assemble(instructions)[offset:])[0] 
                    addCounter = 0
                    if self.is_64:
                        postLanding = Shellcode.disassemble64(Shellcode.assemble64(instructions)[offset:])
                    else:
                        postLanding = Shellcode.disassemble(Shellcode.assemble(instructions)[offset:])
                    instructionsCopy = instructions
                    findMore = True
                    while findMore:
                        try:
                            toAdd=instructionsCopy.index(landingInstruction)
                            shouldReturn = True
                            for i in range(len(instructions)-offset):
                                if instructions[i+offset]!=postLanding[i]:
                                    shouldReturn = False
                            if shouldReturn==False:
                                if instructionsCopy[toAdd:].index(landingInstruction)==0:
                                    break
                                continue
                            else:
                                addCounter += 1
                                targetIndexArray.append(toAdd)
                            if instructionsCopy[toAdd:].index(landingInstruction)==0:
                                break
                        except ValueError:
                            findMore = False
                    if AddCounter == 0:
                        if self.is_64:
                            landingInstruction = Shellcode.disassemble64(Shellcode.assemble64(instructions)[0:offset+1])[offset]
                        else:
                            landingInstruction = Shellcode.disassemble(Shellcode.assemble(instructions)[0:offset+1])[offset]
        self.jumpTargets = targetIndexArray
        return targetIndexArray
    
    #Add relative version 
    def findJumpTargets(self, instructions:list) -> list: 
        indexArray = []
        targetIndexArray = []
        jumpFounds = findJump(instructions)
        for i in jumpFounds: #i here is an element, int, which is a valid element of instructions
            offset = int(instructions[i].split(" ")[1],16)
            instructions[i] = instructions[i].split(" ")[0]+" "+str(hex(offset))
            if self.is_64:
                landingInstruction = Shellcode.disassemble64(Shellcode.assemble64(instructions)[offset:])[0]
                postLanding = Shellcode.disassemble64(Shellcode.assemble64(instructions)[offset:])
            else:
                landingInstruction = Shellcode.disassemble(Shellcode.assemble(instructions)[offset:])[0]
                postLanding = Shellcode.disassemble(Shellcode.assemble(instructions)[offset:])
            instructionsCopy = instructions
            findMore = True
            while findMore:
                try:
                    toAdd=instructionsCopy.index(landingInstruction)
                    shouldReturn = True
                    for i in range(len(instructions)-offset):
                        if instructions[i+offset]!=postLanding[i]:
                                shouldReturn = False #Watch for typo
                    if shouldReturn==False:
                        if instructionsCopy[toAdd:].index(landingInstruction)==0:
                            break
                        continue
                    else:
                        targetIndexArray.append(toAdd)
                    if instructionsCopy[toAdd:].index(landingInstruction)==0:
                        break
                except ValueError:
                    findMore = False
        return targetIndexArray
    
    #@debughook_verbose
    #Note to self, next time there is a jump target error, checl here
    #Breaks with meterpreter/reverse_https
    def findJumpTargetsRelative(self, instructions:list) -> list: 
        indexArray = []
        targetIndexArray = []
        #print(f"JumpIndexes Length: {len(self.jumpIndexes)}")
        for ind, i in enumerate(self.jumpIndexes):  #USE self.jumpIndexes
            #print(instructions[i])
            #print(i)
            offset = int(instructions[i].split(" ")[1],16)
            compareToOffset = 0x0
            if offset>=0:
                for j in range(i,len(instructions)):
                    #print(targetIndexArray)
                    #print("MORE")
                    if compareToOffset>=offset:#Must be exact offset, THIS COULD BE A PROBLEM LATER
                        #Make sure it's not 1 index off
                        debugJumpTargets.append(i)
                        targetIndexArray.append(j)
                        #print(f"Added Target index after: {j}")
                        break
                    if self.is_64:
                        compareToOffset += int(hex(len(Shellcode.assemble64([instructions[j]]))), 16)
                    else:
                        compareToOffset += int(hex(len(Shellcode.assemble([instructions[j]]))), 16)
            elif offset<0:
                for j in range(i-1, 0, -1):
                    #print(targetIndexArray)
                    #print("LESS")
                    if self.is_64:
                        compareToOffset-=len(Shellcode.assemble64([instructions[j]]))
                    else:
                        compareToOffset-=len(Shellcode.assemble([instructions[j]]))
                    if compareToOffset<=offset:
                        debugJumpTargets.append(i)
                        targetIndexArray.append(j)
                        #print(f"Added Target index before: {j}")
                        break
        self.jumpTargets = targetIndexArray
        if len(self.jumpTargets)!=len(self.jumpIndexes):
            print(self.jumpIndexes)
            print(self.jumpTargets)
            raise ValueError("Unequal number of jumps and targets")
        return targetIndexArray
    
    def getRelativeJmpOffset(self, instructions:list, jumpIndies) -> None:
        for index in jumpIndies:
            if self.is_64:
                length = len(Shellcode.assemble64(instructions[0:index])) #It is doing eax instead of rax
            else:
                length = len(Shellcode.assemble(instructions[0:index]))
            if "loop" in instructions[index]:
                continue
            instructions[index] = instructions[index].split(" ")[0]+ " " + str(hex(int(instructions[index].split(" ")[1], 16)-length))
    
    def refresh_jumps(self, instructions:list[str]) -> None:
        for i, jumpInd in enumerate(self.jumpIndexes):
            targetInd:int = self.jumpTargets[i]
            jump_addition:int = 0
            if jumpTargets[i]<self.jumpIndexes[i]:
                for i in instructions[jumpTargets[i]:jumpIndexes[i]+1]:
                    if self.is_64:
                        jump_addition -= len(Shellcode.assemble64(i))
                    else:
                        jump_addition -= len(Shellcode.assemble(i))
            else:
                for i in instructions[jumpIndexes[i]+1:jumpTargets[i]]:
                    if self.is_64:
                        jump_addition += len(Shellcode.assemble64(i))
                    else:
                        jump_addition += len(Shellcode.assemble(i))
            instructions = instructions[jumpInd].split(" ")[0] + " " + str(hex(jump_addition))

    def sort_jump_indexes(self) -> None:
        #Sort its corresponding target
        self.jumpIndexes.sort()

    def move_instructions(self, instructions:list[str], current_inds:list[int], new_inds:list[int]) -> None:
        #Copy the instruction and move it
        for (current_ind, new_ind) in zip(current_inds, new_inds):
            if current_ind in self.jumpTargets:
                self.jumpTargets[self.jumpTargets.index(current_ind)] = new_ind
            #If new_ind's <= a jump target or index, increment it by 1
            for i, (jump, target) in enumerate(zip(self.jumpIndexes, self.jumpTargets)):
                if new_ind<=jump:
                    jumpIndexes[i]+=1
                if new_ind<=target:
                    jumpTargets[i]+=1
            self.sort_jump_indexes()
            self.refresh_jumps()

    #Meant to be used inside a decorator
    #@debughook_verbose
    def insert_bytes(self, instructions:list[str], added_bytes:int, index:int, absolute:bool, shift_target:bool = None, include_if_eq = None) -> None:
        if shift_target is None:
            shift_target = False
        if include_if_eq is None:
            include_if_eq = True
        addedTypes = []
        #JUMPADDITION IS WHAT IS BEING ADDED OR SUBBED FROM THE JUMP
        #If len of toAdd is invalid, then just add 0

        #Check the jump to see if it is being modified if it is out of scope
        for i in range(len(self.jumpIndexes)):

            self.jumpAddition.append([])
            if index<self.jumpIndexes[i] and absolute:
                if self.is_64:
                    potentialAdd = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+added_bytes))#Since it is not relative, I gotta do this
                else:
                    potentialAdd = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+added_bytes))#Since it is not relative, I gotta do this
                if self.jumpTargets[i]<self.jumpIndexes[i] and index<=self.jumpTargets[i]: #If backwards and before the target
                    for j in range(i, len(self.jumpIndexes)):#Update jump offsets as well
                        if self.is_64:
                            instructions[self.jumpIndexes[j]]= instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+added_bytes))#Accounts for differences in each instruction
                        else:
                            instructions[self.jumpIndexes[j]]= instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+added_bytes))#Accounts for differences in each instruction
                    if self.is_64:
                        self.jumpAddition[i].append(added_bytes)
                    else:
                        self.jumpAddition[i].append(added_bytes)
                elif self.jumpTargets[i]<self.jumpIndexes[i] and index>self.jumpTargets[i]: #If backwards and after the target
                    instructions[i] = potentialAdd
                    if i+1<len(self.jumpIndexes): #Add bytes to future jumps
                        for j in range(i+1, len(self.jumpTargets)):
                            if self.is_64:
                                instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+added_bytes))#Accounts for differences in each instruction
                            else:
                                instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+added_bytes))#Accounts for differences in each instruction
                    self.jumpAddition[i].append(0)#-len(assemble([toAdd]))) #It is 0 because it is location relative to the start of the executable code
                else:
                    for j in range(i+1, len(self.jumpIndexes)):
                        instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0] + " "+str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1], 16)))
                    if self.is_64:
                        self.jumpAddition[i].append(added_bytes)
                    else:
                        self.jumpAddition[i].append(added_bytes)
            elif index>self.jumpIndexes[i] and index<=self.jumpTargets[i]:#If jumpIndexes<index<jumpTargets, if inserting between
                
                if self.is_64:
                    addedTypes.append("Between Before")
                    self.jumpAddition[i].append(added_bytes)
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+added_bytes))
                else:
                    addedTypes.append("Between Before")
                    self.jumpAddition[i].append(added_bytes)
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+added_bytes))
                    if not shift_target:
                        pass
            elif index>self.jumpTargets[i] and index<=self.jumpIndexes[i]:#if target<index<=jump
                #Logic error here, it is not subing corectly
                #print(f"\n\n\n\nLOGTIC ERROR: {instructions[self.jumpIndexes[i]]}\n\n\n\n")
                #print()
                if self.is_64:
                    self.jumpAddition[i].append(added_bytes)
                    shellcode = Shellcode.assemble64(instructions)
                    machineCodeJump = shellcode.index(Shellcode.assemble64(instructions[self.jumpIndexes[i]:]))
                    india = machineCodeJump+int(instructions[self.jumpIndexes[i]].split(" ")[1], 16)-added_bytes
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble64(instructions[self.jumpTargets[i]:self.jumpIndexes[i]]))-added_bytes)
                    addedTypes.append("Between Backwards")
                else:
                   # print(self.jumpIndexes[i])
                    #print(instructions[self.jumpIndexes[i]])
                    self.jumpAddition[i].append(added_bytes)
                    shellcode = Shellcode.assemble(instructions)
                    machineCodeJump = shellcode.index(Shellcode.assemble(instructions[self.jumpIndexes[i]:]))
                    india = machineCodeJump+int(instructions[self.jumpIndexes[i]].split(" ")[1], 16)-added_bytes
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble(instructions[self.jumpTargets[i]:self.jumpIndexes[i]]))-added_bytes)
                    addedTypes.append("Between Backwards")
            elif index==self.jumpTargets[i] and index<=self.jumpIndexes[i]:#if target<=index<jump
                if not shift_target:
                    pass
            elif index<=self.jumpTargets[i] and index<=self.jumpIndexes[i]:
                addedTypes.append("Below Both")

    def update_subroutines(self, toAdd:str, index:int, absolute:bool, shift_target:bool = None, include_if_eq = None) -> None:
        if shift_target is None:
            shift_target = False
        if include_if_eq is None:
            include_if_eq = True
        added_bytes:int = len(Shellcode.assemble64([toAdd]) if self.is_64 else Shellcode.assemble([toAdd]))
        for routine_point, routine_ind in enumerate(self.jump_split_by_index):
            if index<=routine_ind and not include_if_eq:
                self.jump_split_by_index[routine_point]+=1
                self.jump_split_by_offset[routine_point]+=added_bytes
            elif index==routine_ind and include_if_eq:
                pass
            elif index<routine_ind and include_if_eq:
                self.jump_split_by_index[routine_point]+=1
                self.jump_split_by_offset[routine_point]+=added_bytes

    #@debughook_verbose
    def insertWithCare(self, instructions:list[str], toAdd:str, index:int, absolute:bool, shift_target:bool = None, include_if_eq = None, shift_jump = True) -> None:
        if shift_target is None:
            shift_target = False
        if include_if_eq is None:
            include_if_eq = True
        instructions.insert(index, toAdd)
        addedTypes = []
        self.update_subroutines(toAdd, index, absolute, shift_target, include_if_eq)
        #JUMPADDITION IS WHAT IS BEING ADDED OR SUBBED FROM THE JUMP
        #If len of toAdd is invalid, then just add 0
        for i in range(len(self.jumpIndexes)):

            self.jumpAddition.append([])
            #print(i)
            #print(self.jumpIndexes)
            #print(self.jumpIndexes[0])
            #print(self.jumpTargets)
            #print(self.jumpTargets[0])

            #print(len(self.jumpIndexes))
            #print(len(self.jumpTargets))
            if index<self.jumpIndexes[i] and absolute:
                if self.is_64:
                    potentialAdd = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+len(Shellcode.assemble64([toAdd]))))#Since it is not relative, I gotta do this
                else:
                    potentialAdd = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+len(Shellcode.assemble([toAdd]))))#Since it is not relative, I gotta do this
                if self.jumpTargets[i]<self.jumpIndexes[i] and index<=self.jumpTargets[i]: #If backwards and before the target
                    for j in range(i, len(self.jumpIndexes)):#Update jump offsets as well
                        if self.is_64:
                            instructions[self.jumpIndexes[j]]= instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+len(Shellcode.assemble64([toAdd]))))#Accounts for differences in each instruction
                        else:
                            instructions[self.jumpIndexes[j]]= instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+len(Shellcode.assemble([toAdd]))))#Accounts for differences in each instruction
                        self.jumpIndexes[j]+=1
                        self.jumpTargets[j] += 1
                    if self.is_64:
                        self.jumpAddition[i].append(len(Shellcode.assemble64([toAdd])))
                    else:
                        self.jumpAddition[i].append(len(Shellcode.assemble([toAdd])))
                elif self.jumpTargets[i]<self.jumpIndexes[i] and index>self.jumpTargets[i]: #If backwards and after the target
                    instructions[i] = potentialAdd
                    for j in range(i, len(self.jumpIndexes)):#Add offset of bytes to other jumps too
                        self.jumpIndexes[j]+=1
                    if i+1<len(self.jumpIndexes): #Add bytes to future jumps
                        for j in range(i+1, len(self.jumpTargets)):
                            if self.is_64:
                                instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+len(Shellcode.assemble64([toAdd]))))#Accounts for differences in each instruction
                            else:
                                instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1],16)+len(Shellcode.assemble([toAdd]))))#Accounts for differences in each instruction
                            self.jumpTargets[j]+=1
                    self.jumpAddition[i].append(0)#-len(assemble([toAdd]))) #It is 0 because it is location relative to the start of the executable code
                else:
                    for j in range(i+1, len(self.jumpIndexes)):
                        self.jumpIndexes[j] += 1
                        self.jumpTargets[j] += 1
                        instructions[self.jumpIndexes[j]] = instructions[self.jumpIndexes[j]].split(" ")[0] + " "+str(hex(int(instructions[self.jumpIndexes[j]].split(" ")[1], 16)))
                    if self.is_64:
                        self.jumpAddition[i].append(len(Shellcode.assemble64(toAdd)))
                    else:
                        self.jumpAddition[i].append(len(Shellcode.assemble(toAdd)))
            elif index>self.jumpIndexes[i] and index<=self.jumpTargets[i]:#If jumpIndexes<index<jumpTargets, if inserting between
                if self.is_64:
                    addedTypes.append("Between Before")
                    self.jumpAddition[i].append(len(Shellcode.assemble64([toAdd])))
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+len(Shellcode.assemble64([toAdd]))))
                    if not shift_target:
                        self.jumpTargets[i]+=1
                else:
                    addedTypes.append("Between Before")
                    self.jumpAddition[i].append(len(Shellcode.assemble([toAdd])))
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +str(hex(int(instructions[self.jumpIndexes[i]].split(" ")[1],16)+len(Shellcode.assemble([toAdd]))))
                    if not shift_target:
                        self.jumpTargets[i]+=1
            elif index==self.jumpIndexes[i] and index<self.jumpTargets[i]:#If jumpIndexes<index<jumpTargets, if inserting between
                self.jumpIndexes[i]+=1
                if not shift_target:
                    self.jumpTargets[i]+=1
            elif index>self.jumpTargets[i] and index<=self.jumpIndexes[i]:#if target<index<=jump
                if self.is_64:
                    self.jumpAddition[i].append(len(Shellcode.assemble64([toAdd])))
                    #if index==self.jumpIndexes[i] and not shift_jump:
                    #    pass
                    #else:
                    self.jumpIndexes[i]+=1

                    shellcode = Shellcode.assemble64(instructions)
                    machineCodeJump = shellcode.index(Shellcode.assemble64([instructions[self.jumpIndexes[i]]]))
                    india = machineCodeJump+int(instructions[self.jumpIndexes[i]].split(" ")[1], 16)-int(len(Shellcode.assemble64([toAdd])))
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble64(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))
                    addedTypes.append("Between Backwards")
                else:
                    self.jumpAddition[i].append(len(Shellcode.assemble([toAdd])))
                    #if index==self.jumpIndexes[i] and not shift_jump:
                    #    pass
                    #else:
                    self.jumpIndexes[i]+=1
                    #print(self.jumpIndexes)
                    shellcode = Shellcode.assemble(instructions)
                    machineCodeJump = shellcode.index(Shellcode.assemble([instructions[self.jumpIndexes[i]]]))
                    #print(machineCodeJump)
                    #print(self.jumpIndexes[i])
                    #print(instructions[self.jumpIndexes[i]-1])
                    #print(self.jumpTargets[i])
                    #print(instructions)
                    try:
                        india = machineCodeJump+int(instructions[self.jumpIndexes[i]].split(" ")[1], 16)-int(len(Shellcode.assemble([toAdd])))
                    except:
                        #print(instructions)
                        #print(self.jumpIndexes)
                        #for x in self.jumpIndexes:
                        #    print(instructions[x]) 
                        #print(self.jumpTargets)
                        print("JumpInstructions not pointing to all jump instructions")
                        breakpoint()
                        exit()
                    instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))
                    addedTypes.append("Between Backwards")
            elif index==self.jumpTargets[i] and index<=self.jumpIndexes[i] and not include_if_eq:#if target<=index<jump
                self.jumpIndexes[i]+=1
                if not shift_target:
                    self.jumpTargets[i]+=1
                addedTypes.append("Between Backwards")
                #This will insert before the target
                #if self.is_64:
                #    self.jumpAddition[i].append(len(Shellcode.assemble64([toAdd])))
                #    if include_if_eq:
                #        instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble64(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))
                #else:
                #    self.jumpAddition[i].append(len(Shellcode.assemble([toAdd])))
                #    if include_if_eq:
                #        instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))
            elif index==self.jumpTargets[i] and index<=self.jumpIndexes[i] and include_if_eq:#if target<=index<jump
                self.jumpIndexes[i]+=1
                if not shift_target:
                    self.jumpTargets[i]+=1
                addedTypes.append("Between Backwards")
                #This will insert before the target
                if self.is_64:
                    self.jumpAddition[i].append(len(Shellcode.assemble64([toAdd])))
                    if include_if_eq:
                        instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble64(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))
                else:
                    self.jumpAddition[i].append(len(Shellcode.assemble([toAdd])))
                    if include_if_eq:
                        instructions[self.jumpIndexes[i]] = instructions[self.jumpIndexes[i]].split(" ")[0]+ " " +hex(-len(Shellcode.assemble(instructions[self.jumpTargets[i]:self.jumpIndexes[i]])))


            elif index<=self.jumpTargets[i] and index<=self.jumpIndexes[i]:
                addedTypes.append("Below Both")
                self.jumpIndexes[i]+=1
                if not shift_target:
                    self.jumpTargets[i]+=1
    
    @staticmethod
    def fixBadMnemonics(instructions:list) -> list:
        returnable = instructions
        for i in range(len(returnable)):#make it mutable
            instruction = returnable[i]
            if instruction.split(" ")[0]=="lods": #Not used ATM
                newInstruction="lods "
                for j in range(1, len(instruction.split(" "))):
                    newInstruction+=instruction.split(" ")[j]+" "
                returnable[i] = newInstruction
        return returnable
    

    @staticmethod
    def fixBadOperands(instructions:list, map:list) -> list:
        returnable = instructions
        for i in range(len(returnable)):#make it mutable
            instruction = returnable[i]
            if instruction.split(" ")[0]=="lods"or instruction.split(" ")[0]=="lodsb": #Not used ATM
                newInstruction="lods "
                for j in range(1, len(instruction.split(" "))):
                    newMnemonic = ""
                    if(j==1):
                        newInstruction+="al, "
                    else:
                        newInstruction+=instruction.split(" ")[j]+" "
                returnable[i] = newInstruction
        return returnable
    
    @staticmethod
    def disassemble(string:str, arch=CS_ARCH_X86, mode=CS_MODE_32) -> list:
        disas = Cs(arch, mode) #Preparing for rewrite
        string_temp = string
        instruction_ind = 0
        bytes_loc = 0x0
        instructions = []
        #print(disas.disasm(string_temp, 0x1000))
        #for i in range(0, +1): #get i.Instruction Count
        for i in disas.disasm(string_temp, 0x1000):#Update to be compatible with larger shellcodes
            instructions.append(f"{i.mnemonic} {i.op_str}")
            instruction_ind += 1
            bytes_loc+=i.size
            #print(f"{i.mnemonic} {i.op_str}")
            #if instruction_ind>249:
            #    string_temp = string_temp[bytes_loc:] #does not loop yet
            #    raise ValueError("Instruction length too long")
        if bytes_loc!=len(string_temp):
            raise ValueError(f"\x1b[31mCapstone could not disassemble all instructions. There is likely a bad instruction in your shellcode near offset: {hex(bytes_loc)}.\x1b[0m")
        return instructions

    def i_disasm(self, string:str):
        disas = Cs(self.arch[0], self.mode) #Preparing for rewrite
        string_temp = string
        instruction_ind = 0
        bytes_loc = 0x0
        instructions = []
        #print(disas.disasm(string_temp, 0x1000))
        #for i in range(0, +1): #get i.Instruction Count
        for i in disas.disasm(string_temp, 0x1000):#Update to be compatible with larger shellcodes
            instructions.append(f"{i.mnemonic} {i.op_str}")
            instruction_ind += 1
            bytes_loc+=i.size
            #print(f"{i.mnemonic} {i.op_str}")
            #if instruction_ind>249:
            #    string_temp = string_temp[bytes_loc:] #does not loop yet
            #    raise ValueError("Instruction length too long")
        if bytes_loc!=len(string_temp):
            raise ValueError(f"\x1b[31mCapstone could not disassemble all instructions. There is likely a bad instruction in your shellcode near offset: {hex(bytes_loc)}.\x1b[0m")
        return instructions

    @staticmethod
    def disassemble_loop(string:str, index) -> list: #This also has to be updated
        disas = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = []
        byteLocs = b''
        for i in disas.disasm(string, 0x1000):
            instructions.append(f"{i.mnemonic} {i.op_str}")
            if "loop" in str(i.mnemonic) and len(instructions)-1==index:
                byteLocs = i.bytes
        return byteLocs

    @staticmethod
    def disassemble_loop64(string:str, index) -> list:
        disas = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = []
        byteLocs = b''
        for i in disas.disasm(string, 0x1000):
            instructions.append(f"{i.mnemonic} {i.op_str}")
            if "loop" in str(i.mnemonic) and len(instructions)-1==index:
                byteLocs = i.bytes
        return byteLocs

    @staticmethod
    def disassemble64(code:str) -> list:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        string_temp = code
        instructions = []
        instruction_ind = 0
        bytes_loc=0
        for i in md.disasm(code, 0x1000):
            try:
                instructions.append(i.mnemonic+" " + i.op_str)
                instruction_ind +=1
                bytes_loc+=int(i.size)
            except:
                print("\x1b[31m\nError disassembling instruction:") #lodsb is breaking it
                print(instruction)
                exit()
        #    if instruction_ind>249:
        #        string_temp = string_temp[bytes_loc:] #does not loop yet
        #        raise ValueError("Instruction length too long")
        if bytes_loc!=len(string_temp):
            raise ValueError(f"\x1b[31mCapstone could not disassemble all instructions. There is likely a bad instruction in your shellcode near offset: {hex(bytes_loc)}.\x1b[0m")
        return instructions

    @staticmethod
    def assemble(instructions:list, arch=KS_ARCH_X86, mode=KS_MODE_32) -> bytes:
        assembler = Ks(arch, mode)
        returnable = b""
        for ind, instruction in enumerate(instructions):
            try:
                machineCode, _ = assembler.asm(instruction)
            except:
                print("\x1b[31m\nError assembling instruction:") #lodsb is breaking it
                print(instruction)
                print(ind)
                breakpoint()
                exit()
            for byte in machineCode:
                returnable += bytes.fromhex(format(byte,"02x"))
        return returnable


    @staticmethod
    def assemble64(instructions:list) -> str:
        assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        returnable = b""
        for instruction in instructions:
            try:
                machineCode, _ = assembler.asm(instruction)
            except:
                print("\x1b[31m\nError assembling 64-bit instruction:") #lodsb is breaking it
                print(instruction)
                exit()
            for byte in machineCode:
                returnable += bytes.fromhex(format(byte,"02x"))
        return returnable

    #@staticmethod
    #def assemble_arm(instructions:list[str]) -> str:
    #    pass

    #During rewrite, I will merge all of these into 1 function


def findall(string:str, phrase:str) -> list:
    returnable = []
    findIndex = 0
    while True:
        loc = string.find(phrase, findIndex)
        if loc<=0:
            break
        if string[loc-1]!=" " and string[loc-1] !="[":# and string[loc-1] !=","# and (phrase =="ax" or phrase=="ah" or phrase=="al" or phrase=="bx" or phrase=="bh" or phrase=="bl" or phrase=="cl" or phrase=="ch" or phrase=="cx" or phrase=="dx" or phrase=="dl" or phrase=="dh"): #MAKE SURE THERE IS NO jecxx and jcxz
            findIndex += loc+len(phrase)+1
        else:
            returnable.append(loc)
            findIndex += loc+len(phrase)
    return returnable

