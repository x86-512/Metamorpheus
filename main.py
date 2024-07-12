from register_swap import *
from essentials import *
from dead_code import *
from logic_swap import *
#from encryption import * # Work in progress

import sys

def print_help():
    print("Syntax:")
    print("-s: Register Swap (\x1b[4mEXPERIMENTAL\x1b[0m)")
    print("-r: Logic replacement")
    print("-d: Dead code insertion")


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
    valid_flags:list[str] = ['d', 'r', 's', 'x']
    return False if sys.argv[1][0] != '-' else all(flag in valid_flags for flag in sys.argv[1][1:])

def main() -> None:
    #print("\n")
    #print(code.jumpAddition)
    args_present = True
    try:
        sys.argv[1]
    except IndexError:
        args_present = False

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
        print(instructions)
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
        #updatedInstr = code.encrypt(updatedInstr)
        print(f"\nUpdated Instructions:\n{updatedInstr}\n")
        if code.is_64_bit():
            print(f"Shellcode:\n{bytesToString(Shellcode.assemble64(updatedInstr))}")
        else:
            print(f"Shellcode:\n{bytesToString(Shellcode.assemble(updatedInstr))}")
        print(f"\nShellcode Length: {len(Shellcode.assemble(updatedInstr))} bytes")
    else:
        print_help()

if __name__=="__main__":
    main()
