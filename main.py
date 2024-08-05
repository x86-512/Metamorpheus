from modules.register_swap import *
from modules.dead_code import *
from modules.logic_swap import *
from modules.garbage_jump import *
from essentials import * #All the modules import from the main file's directory automatically, so there is no need to place this in modules
#from encryption import * # Work in progress

import compilers.win as wincomp #Use xor to avoid the bad chars problem
import compilers.unix as unicomp #Use MMAP and stuff to actually get the thing to run, it will need to be RWX tho

import sys

def print_help():
    print("Syntax:")
    print("-s: Subroutine Register Swap (\x1b[4mEXPERIMENTAL\x1b[0m)")
    print("-x: Full Register Swap (\x1b[4mLimited to 63 bytes or less\x1b[0m)")
    print("-r: Logic replacement")
    print("-d: Dead code insertion")
    print("-g: Garbage byte insertion")


def findBetweenEach(string:str, phrase:str) -> list:
    returnable:list = []
    for i in range(0, len(findall_regular(string, phrase)), 2):#update it to get rid of the " and anything outside of it
        returnable.append(string[findall_regular(string, phrase)[i]:findall_regular(string, phrase)[i+1]])
    #For each pair, add a list between each instance
    #If odd, ignore it
    if returnable ==[]:
        returnable = [string]
    return returnable


#Remember to come here if you get an assembly error
def loadShellcodeFromFile(fileName:str) -> Shellcode:
    #Line 1 is marked by arch: either 32 or 64
    #actual_code = b""
    actual_code = ""
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
    except FileNotFoundError:
        print("Shellcode.txt not found")
        exit()
    return Shellcode(actual_code, is64)
    
def verify_args():
    valid_flags:list[str] = ['d', 'r', 's', 'x', 'g']
    return False if sys.argv[1][0] != '-' else all(flag in valid_flags for flag in sys.argv[1][1:])

def main() -> None:
    #print("\n")
    #print(code.jumpAddition)
    args_present = True
    try:
        sys.argv[1]
    except IndexError:
        args_present = False

    code:Shellcode = loadShellcodeFromFile("shellcode.txt")
    if code.is_64_bit():
        instructions = Shellcode.disassemble64(code.getCode())
    else:
        instructions = Shellcode.disassemble(code.getCode())

    if args_present:
        if(not verify_args()):
            print_help()
            return

        code:Shellcode = loadShellcodeFromFile("shellcode.txt")
        if code.is_64_bit():
            instructions = Shellcode.disassemble64(code.getCode())
        else:
            instructions = Shellcode.disassemble(code.getCode())

        instructions = Shellcode.fixBadMnemonics(instructions)
        instructions = Shellcode.fixJumpErrors(instructions)
        print(f"\nOriginal Instructions: {instructions}")
        jumpIndexesOffset = code.findJump(instructions) 
        code.getRelativeJmpOffset(instructions, jumpIndexesOffset)
        code.findJumpTargetsRelative(instructions)
        updatedInstr = instructions

        if sys.argv[1].find("d")>-1:
            updatedInstr = code.addDeadCode(instructions)
        #print(updatedInstr)
        #print("\n"*10)
        if sys.argv[1].find("r")>-1:
            updatedInstr = code.logic_replacement(updatedInstr)
        if (sys.argv[1].find("s"))>-1 and (sys.argv[1].find("x")==-1):
            #Make sure it is not in a loop, also randomize swapping indexes
            start_of_swap = max(find_first_register_uses(updatedInstr, ["rax", "rcx", "rdx", "rbx"]))

            #not inserting xchg instructions
            reg_swap_locs = code.update_bounds_of_reg_swap(updatedInstr, start_of_swap)
            updatedInstr = code.registerSwap(updatedInstr, reg_swap_locs[0], reg_swap_locs[1])

        if (sys.argv[1].find("x"))>-1:
            updatedInstr = code.registerSwap(updatedInstr)

        if 'g' in sys.argv[1]:
            code.insert_garbage(updatedInstr)
        else:
            if code.is_64_bit():
                code.shellcode = Shellcode.assemble64(updatedInstr)
            else:
                code.shellcode = Shellcode.assemble(updatedInstr)

        if len(sys.argv)>=3:
            if 'w' in sys.argv[2]:
                print("Windows functionality will be added soon")
                pass
            if 'u' in sys.argv[2]:
                unicomp.compile(64 if code.is_64 else 32,code.string)

        #updatedInstr = code.encrypt(updatedInstr)
        print(f"\nUpdated Instructions:\n{updatedInstr}\n")
        print(f"Shellcode:\n{code.string}")
        print(f"\nShellcode Length: {code.length} bytes")
    else:
        print_help()

if __name__=="__main__":
    main()
