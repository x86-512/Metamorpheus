from essentials import *
from random import randrange

def anti_trap(self, instructions) -> list[str]:
    flag_register = gen_random_register()
    if self.is_64:
        flag_register[0]='r'
    self.insertWithCare(instructions, f"xor {flag_register}, {flag_register}", 0, False)
    self.insertWithCare(instructions, f"mov e{flag_register[1:]}, 0xdeadbfef", 1, False)
    self.insertWithCare(instructions, f"sub e{flag_register[1:]}, 0xdeadbeef", 2, False) #Will change to be a random sub pair later
    #To get 100
    self.insertWithCare(instructions, "pushfd", 3, False)
    
    if self.is_64:
        self.insertWithCare(instructions, f"and qword ptr [rsp], {flag_register}", 4, False)
    else:
        self.insertWithCare(instructions, f"and dword ptr [esp], {flag_register}", 4, False)
    self.insertWithCare(instructions, f"pop {flag_register}", 5, False)
    cmp_z_method = ["cmp", "test"]
    self.insertWithCare(instructions, f"{cmp_z_method[randrange(0, len(cmp_z_method))]} {flag_register}, {flag_register}", 6, False)
    crash_instr = f"jmp {flag_register}"
    je_index = 7
    crash_index = 8
    je_target = 9
    self.insertWithCare(instructions, f"jz {hex(len(Shellcode.assemble64([crash_instr]) if self.is_64 else Shellcode.assemble([crash_instr]))+0x2)}", je_index, False)

    self.insertWithCare(instructions, crash_instr, crash_index, False) #To crash program
    self.insertWithCare(instructions, "nop", je_target, False)
    self.jumpIndexes.insert(0, je_index)
    self.jumpTargets.insert(0, je_target)
    return instructions


    
Shellcode.anti_trap = anti_trap
