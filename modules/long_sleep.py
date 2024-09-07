from essentials import *
from random import randint

def long_sleep(self, instructions:list[str]):
    counter_register = full_x86_regs[randint(0, len(full_x86_regs)-1)]
    loop_defined = False
    loop_count:str = "0x00000000"
    while not loop_defined:
        loop_count = "0x%08x"%randint(2147483648, 4294967295)
        loop_defined = not contains_bad_chars(loop_count)

    self.insertWithCare(instructions, f"xor {counter_register}, {counter_register}", 0, False)
    loop_start_ind:int = 1
    loop_jump_ind:int = 4
    self.insertWithCare(instructions, f"nop", loop_start_ind, False)
    self.insertWithCare(instructions, f"inc {counter_register}", 2, False)
    self.insertWithCare(instructions, f"cmp {counter_register}, {loop_count}", loop_jump_ind-1, False)
    loop_len = len(Shellcode.assemble64(instructions[loop_start_ind:loop_jump_ind]) if self.is_64 else Shellcode.assemble(instructions[loop_start_ind:loop_jump_ind]))#Everything up to loop jump ind
    #self.insertWithCare(instructions, f"jl -{'0x%02x'%(loop_len+2)}", loop_jump_ind, False)

    self.add_jump(instructions, loop_jump_ind, loop_start_ind, "jl")
    
    return instructions

Shellcode.long_sleep = long_sleep
