from essentials import *
from random import randint

#This is meant to be a final function, don't expect to get anything when you disassemble this

def contains_sublist(lst, sublist):
    length = len(sublist)
    return any((sublist==lst[i:length+i]) for i in range(len(lst)-length+1))

def generate_random_bytes(num_bytes:int) -> bytes:
    returnable:bytes = b""
    for i in range(num_bytes):
        while True:
            rand_int = randint(0, 0xFF)
            rand_hex = format(rand_int, "02x")
            if rand_hex!="00" and rand_hex!="04" and rand_hex!="05" and rand_hex!="09" and rand_hex!="0a" and rand_hex!="0A" and rand_hex!="20":
                returnable += bytes.fromhex(rand_hex)
                break
    return returnable

#@adding_bad_bytes
def insert_garbage(self, instructions) -> int:
    shellcode_byte_locations = []
    jump_target:int = randint(1,int((len(instructions)-1)))
    jump_index:int = jump_target - 1
    num_bytes:int = randint(2,16)
    self.insertWithCare(instructions, "nop", jump_target, False)
    self.add_jump(instructions, jump_index, jump_target) #Get the index by assemble to the end

    garb_bytes:bytes = generate_random_bytes(num_bytes)

    self.insert_bytes(instructions, len(garb_bytes), jump_target, False)

    self.dec_jump(instructions, jump_index)
    if self.is_64:
        self.shellcode = Shellcode.assemble64(instructions)
        shellcode_byte_locations.append(self.shellcode.find(Shellcode.assemble64(instructions[jump_target:])))
    else:
        self.shellcode = Shellcode.assemble(instructions)
        shellcode_byte_locations.append(self.shellcode.find(Shellcode.assemble(instructions[jump_target:])))
    #for i in shellcode_byte_locations:
    #breakpoint()
    for i in shellcode_byte_locations:
        self.shellcode = self.shellcode[0:i]+garb_bytes+self.shellcode[i:]
    return num_bytes

Shellcode.insert_garbage = insert_garbage
