import random
from essentials import *


#Add dead_sled for a long list of dead code that is outside of any subroutine
useless_instructions = ["nop", "and _, 0x|"]#, "xchg _, _"]
#_ is register, | is F*registersize
#= is random number with no bad chars

useless_sets = [["push _", "pop _"], ["inc _", "dec _"], ["add _, =", "sub _, ="]]

#In next update, check to make sure dead code is changed before critical instructions like jmp, int 0x80
def addDeadCode(self, instructions):
    if len(instructions)>4:
        how_many_to_add = random.randint(1,int(len(instructions)/2))
    else:
        how_many_to_add = 1
    for i in range(how_many_to_add):
        added_set:list = useless_instructions if random.randint(0,1) else useless_sets
        chosen = random.randint(0,len(added_set)-1)
        ind = random.randint(0, len(instructions)-1)
        register = mapNumberToRegister(random.randint(1,4)*10)
        and_replacement = "FFFFFFFFFFFFFFFF"
        if not self.is_64:
            and_replacement = "FFFFFFFF"
            register = mapNumberToRegister(random.randint(1,4)*10+1)
            and_replacement
        num = random_hex(32) if self.is_64 else random_hex(32)
        if type(added_set[chosen])==list and len(added_set[chosen])==2:
            add1 = added_set[chosen][0].replace('_', register).replace('=', num).replace('|', "")

            add2 = added_set[chosen][1].replace('_', register).replace('=', num).replace('|', and_replacement)
            if add1.split(" ")[0]=="add" and self.is_64:
                add1 = add1.replace("r"+register[1:], "e"+register[1:])
            if add2.split(" ")[0]=="sub" and self.is_64:
                add2 = add2.replace("r"+register[1:], "e"+register[1:])
            self.insertWithCare(instructions, add1, ind, False)
            self.insertWithCare(instructions, add2, ind+1, False)
        else:
            new_instr = added_set[chosen]
            new_instr = new_instr.replace('_', register).replace('=', num).replace('|', and_replacement)

            self.insertWithCare(instructions, new_instr, ind, False)
    return instructions
    
Shellcode.addDeadCode = addDeadCode
