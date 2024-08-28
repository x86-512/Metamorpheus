from modules.register_swap import *
from modules.dead_code import *
from modules.logic_swap import *
from modules.garbage_jump import *
from essentials import * #All the modules import from the main file's directory automatically, so there is no need to place this in modules
#from encryption import * # Work in progress

import compilers.win as wincomp #Use xor to avoid bad chars
import compilers.unix as unicomp #Use mmap to allocate better and use xor

import sys

def print_help():
    print("Syntax:")
    #print("-s: Register Swap (\x1b[4mEXPERIMENTAL\x1b[0m)")
    #print("-x: Full Register Swap (\x1b[4mLimited to 63 byte, may cause crashes\x1b[0m)")
    print("-r: Logic replacement")
    print("-d: Dead code insertion")
    print("-g: Garbage byte insertion")
    print("-v: Verbose mode")
    print("Shellcode.txt syntax:\nArch(32 or 64)\nShellcode here, with or without \"")


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
        print("Shellcode.txt not found, please make one and put it in the local directory")
        exit()
    return Shellcode(actual_code, is64)
    
def verify_args():
    valid_flags:list[str] = ['d', 'r', 'g', 'v']
    return False if sys.argv[1][0] != '-' else all(flag in valid_flags for flag in sys.argv[1][1:])

def main() -> None:
    #print("\n")
    #print(code.jumpAddition)
    args_present = True
    try:
        sys.argv[1]
    except IndexError:
        args_present = False
    
    verbose:bool = False
    if 'v' in sys.argv[-1]:
        verbose = True

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
        instructions = code.fixJumpErrors(instructions, code.getCode()) #Update to fix loop instructions

        #Add a verbose option
        if verbose:
            print(f"\nOriginal Instructions: \n{instructions}")

        jumpIndexesOffset = code.findJump(instructions) 
        code.getRelativeJmpOffset(instructions, jumpIndexesOffset) # Breaks the loop

        code.findJumpTargetsRelative(instructions)
        updatedInstr = instructions 

        code.get_subroutines(updatedInstr)
        if "d" in sys.argv[1]:
            updatedInstr = code.addDeadCode(instructions)
        #print(updatedInstr)
        #print("\n"*10)
        if "r" in sys.argv[1]:
            updatedInstr = code.logic_replacement(updatedInstr)
        #if "x" not in sys.argv[1] and "s" in sys.argv[1]:
            #Make sure it is not in a loop, also randomize swapping indexes
            #start_of_swap = max(find_first_register_uses(updatedInstr, ["rax", "rcx", "rdx", "rbx"]))

            #not inserting xchg instructions

            #for instruction in code.jumpIndexes:
            #    print(instructions[instruction])
            #breakpoint()

            #code.jump_out_of_subroutine(updatedInstr, )
            #print(code.jump_split_by_index)
            #reg_swap_locs = code.update_bounds_of_reg_swap(updatedInstr, start_of_swap)

            #print(updatedInstr)
            #print(code.registers_in_subroutine(updatedInstr))
            full_subroutines = code.registers_in_subroutine(updatedInstr)
        #    if len(code.registers_in_subroutine(updatedInstr))==0:
        #        print("Your shellcode does not use the a, b, c, and d registers in the same subroutine")
        #        exit()
        #    reg_swap_conditional_subroutines = full_subroutines[0] 
            #print(reg_swap_conditional_subroutines)
        #    reg_swap_locs = reg_swap_conditional_subroutines[0] if len(reg_swap_conditional_subroutines)>0 else -1
        #    if reg_swap_locs==-1:
        #        print("Register swap not completed due to the required contitions not being met")
        #        exit()
            #print(reg_swap_locs)
        #    else:
        #        updatedInstr = code.registerSwapSubroutine(updatedInstr, reg_swap_conditional_subroutines[0], reg_swap_conditional_subroutines[1]-1)

        #if "x" in sys.argv[1]:
        #    if code.length>63:
        #        print("Your shellcode is too large to use the global register swap feature. Your shellcode should be no longer than 63 bytes.")
        #        exit()
        #    updatedInstr = code.registerSwap(updatedInstr)

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

        #Verbose option here
        if verbose:
            print(f"\nUpdated Instructions:\n{updatedInstr}\n")
        print(f"New Shellcode:\n{code.string}")
        print(f"\nShellcode Length: {code.length} bytes")
    else:
        print_help()

if __name__=="__main__":
    main()
