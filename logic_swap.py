from essentials import *

#Outline:
#xor_replacement is meant to be a lite version of the full instruction

    #Retrieve what is in between the odd " and the even "

def calculate_change_limit(instructions_length) -> int:
    return instructions_length #Temporary limit

#Check for critical instructions for reg-dependednt instructions
def xor_replacement(instructions:list) -> list: #I may rewrite to have instructions be a field in the shellcode class 
    markedTargets = []
    for i in range(len(instructions)):
        instruction = instructions[i]
        for mathInstruction in mathInstructions:
            if instruction.find(mathInstruction)==0:
                markedTargets.append(i)

    for i, markedTargetind in enumerate(markedTargets):
        markedTarget = instructions[markedTargetind]
        number = markedTarget.split(",")[1].split(" ")[1]
        if number[0:2]!="0x":
            continue
        numberLoc = markedTarget.find(markedTarget.split(",")[1].split(" ")[1])
        register = markedTarget.split(" ")[1].split(",")[0]
        xor_set = random_hex_xor_pair(number)
        instructions[markedTargets[i]] = instructions[markedTargets[i]].replace(number, xor_set[0])
        instructions.append(f"xor {register}, {xor_set[1]}") #REPLACE WHEN NECESSARY

def xor_replacement_suggestion(instruction:str) -> list:
    target_num = instruction.split(", ")[1]
    #Unbeautify target_num and check its size, if it is 8 or less, treat it as 32-bit
    arch = get_register_size(instruction)

    if arch==64 and len(unbeautify_hex(target_num))<=10:
        arch=32 #Treat it as 32-bit
    elif arch==64 and len(unbeautify_hex(target_num))>10:
        return [instruction, "0x00000000"]
    xor_pair = random_hex_xor_pair(target_num, arch)
    updated_instruction = instruction.replace(target_num, xor_pair[0])
    returnable:list = [updated_instruction,xor_pair[1]] 
    return returnable

def add_replacement_suggestion(instruction:str) -> list:
    mnemonic = instruction.split(" ")[0]
    target_mnemonic = mnemonic
    if mnemonic=="mov" or mnemonic=="xor":
        target_mnemonic = "add"
    if mnemonic=="sub":
        target_mnemonic = "sub"
    target_num = instruction.split(", ")[1]
    arch = get_register_size(instruction)
    if arch==64 and len(unbeautify_hex(target_num))<=10:
        arch=32 #Treat it as 32-bit
    elif arch==64 and len(unbeautify_hex(target_num))>10:
        return [instruction, "0x00000000"]
    add_pair = random_hex_add_pair(target_num, arch)
    updated_instruction = instruction.replace(target_num, add_pair[0])
    returnable:list = [updated_instruction,add_pair[1], target_mnemonic] 
    return returnable



#IF IT IS ADDED AND THE PREVIOUS INSTRUCTION IS SUB, THEN IT IS subbed
def sub_replacement_suggestion(instruction:str) -> list:
    mnemonic = instruction.split(" ")[0]
    target_mnemonic = mnemonic
    if mnemonic=="mov" or mnemonic=="xor":
        target_mnemonic = "sub"
    if mnemonic=="sub":
        target_mnemonic = "add"
    target_num = instruction.split(", ")[1]
    arch = get_register_size(instruction)
    if arch==64 and len(unbeautify_hex(target_num))<=10:
        arch=32 #Treat it as 32-bit
    elif arch==64 and len(unbeautify_hex(target_num))>10:
        return [instruction, "0x00000000"]
    sub_pair = random_hex_sub_pair(target_num, arch)
    updated_instruction = instruction.replace(target_num, sub_pair[0])
    returnable:list = [updated_instruction,sub_pair[1], target_mnemonic] 
    return returnable

def logic_replacement(self, instructions:list) -> list:
    bad_math_instructions = []
    math_instructions = []
    random_add_limit = calculate_change_limit(len(instructions))
    random_adds = 0
    do_not_change = []
    for i, instruction in enumerate(instructions): #remember, these variables are temporary, editing instruction does nothing to instructions
        to_cont = False
        for j in do_not_change:
            if j==i:
                to_cont = True
        if to_cont==True:
            continue
        try:
            if instruction.split(" ")[0]=="xor" and instruction.split(" ")[2]==instruction.split(" ")[1].replace(",",""):
                if random.randint(0,1):
                    instructions[i]=f"sub {instruction.split(' ')[2]}, {instruction.split(' ')[2]}"
            elif instruction.split(" ")[0]=="sub" and instruction.split(" ")[2]==instruction.split(" ")[1].replace(",",""):
                if random.randint(0,1):
                    instructions[i]=f"xor {instruction.split(' ')[2]}, {instruction.split(' ')[2]}"
        except IndexError:
            pass
        for j in mathInstructions:
            mnemonic = j.split(" ")[0]
            instruction_size = get_register_size(instruction) #Breaks for nops
            #Temporary fix:
            if instruction_size==64:
                continue
            try:
                if(instruction.split(', ')[1][0:2]=="0x"):
                    pass
            except IndexError:
                continue
            if instruction.split(" ")[0]==j and instruction.split(', ')[1][0:2]=="0x":
                if contains_bad_chars(beautify_hex(instruction.split(', ')[1], instruction_size)):
                    targetMnemonic = mnemonic
                    match mnemonic:
                        case "mov":
                            if random.randint(0,1):
                                replacement_suggestions = xor_replacement_suggestion(instruction)
                                targetMnemonic = "xor"
                            else:
                                if random.randint(0,1):
                                    replacement_suggestions = add_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                                else:
                                    replacement_suggestions = sub_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                        case "xor":
                            replacement_suggestions = xor_replacement_suggestion(instruction)
                            targetMnemonic = "xor"
                        case "add":
                            if random.randint(0,1):
                                replacement_suggestions = add_replacement_suggestion(instruction)
                                targetMnemonic = replacement_suggestions[2]
                            else:
                                replacement_suggestions = sub_replacement_suggestion(instruction)
                                targetMnemonic = replacement_suggestions[2]
                        case "sub":
                            if random.randint(0,1):
                                replacement_suggestions = add_replacement_suggestion(instruction)
                                targetMnemonic = replacement_suggestions[2]
                            else:
                                replacement_suggestions = sub_replacement_suggestion(instruction)
                                targetMnemonic = replacement_suggestions[2]
                    if replacement_suggestions[1]=="0x00000000":
                        continue
                    instructions[i] = replacement_suggestions[0]
                    register = instruction.split(" ")[1].split(",")[0]
                    max_reg:int = i+1
                    for k, after_instr in enumerate(instructions[i+1:], start=i+1): #Also check if it is register dependent
                        if after_instr.split(" ")[1:] is not None:
                            for l in after_instr.split(" "): #Good thing this isn't []ed
                                for sub in registerClassMain(register):
                                    for jmp in critical_instrs:
                                        if(sub in l or jmp in l): #CHECK THE ENTIRE REGISTER CLASS
                                            max_reg = k-1
                                            break
                    insert_index = random.randint(i+1, max_reg)
                    self.insertWithCare(instructions, f"{target_mnemonic} {register}, {replacement_suggestions[1]}", insert_index, False)
                elif random_adds<random_add_limit:
                    rand_max = random.randint(3,5)
                    change_to_change = random.randint(0,rand_max+4)
                    if change_to_change<rand_max:#random.randint(0,rand_max-1):
                        targetMnemonic = mnemonic
                        match mnemonic:
                            case "mov":
                                if random.randint(0,1):
                                    replacement_suggestions = xor_replacement_suggestion(instruction)
                                    targetMnemonic = "xor"
                                else:
                                    if random.randint(0,1):
                                        replacement_suggestions = add_replacement_suggestion(instruction)
                                        targetMnemonic = replacement_suggestions[2]
                                    else:
                                        replacement_suggestions = sub_replacement_suggestion(instruction)
                                        targetMnemonic = replacement_suggestions[2]
                            case "xor":
                                replacement_suggestions = xor_replacement_suggestion(instruction)
                                target_mnemonic = "xor"
                            case "add":
                                #If num is less than the target, then add, else subtract
                                if random.randint(0,1):
                                    replacement_suggestions = add_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                                else:
                                    replacement_suggestions = sub_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                            case "sub":
                                if random.randint(0,1):
                                    replacement_suggestions = add_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                                else:
                                    replacement_suggestions = sub_replacement_suggestion(instruction)
                                    targetMnemonic = replacement_suggestions[2]
                        if replacement_suggestions[1]=="0x00000000":
                            continue
                        instructions[i] = replacement_suggestions[0]
                        register = instruction.split(" ")[1].split(",")[0]
                        max_reg:int = i+1
                        for k, after_instr in enumerate(instructions[i+1:], start=i+1): #Also check if it is register dependent
                            if after_instr.split(" ")[1:] is not None:
                                for l in after_instr.split(" "):
                                    for sub in registerClassMain(register):
                                        if(l.find(sub)>-1): #CHECK THE ENTIRE REGISTER CLASS
                                            max_reg = k-1
                                            break
                        try:
                            insert_index = random.randint(i+1, max_reg)
                        except ValueError:
                            insert_index = i+1

                        self.insertWithCare(instructions, f"{targetMnemonic} {register}, {replacement_suggestions[1]}", insert_index, False)
                        random_adds+=1
    
    #now if it doesn't have a bad character, but there is still a mov

    return instructions
                    #self.insertWithCare(instructions, f"xor {register}, {replacement_suggestions[1]}", i+1)
                    #The first index will be the replacement, the second one will be the fixing function
                    #Either xor it or just add it
                #Check if it has bad characters
    #Check if instruction is a math instruction, then check it for bad chars, if so, it WILL be changed
    #Check the arch and see what xor instructions are acceptable, I was thinking about keeping it 32-bit
Shellcode.logic_replacement = logic_replacement

#logic_replacement(["mov eax, 0x0A2020","nop", "nop", "inc ebx", "xor ebx, ebx", "mov ebx, eax", "xor eax, 0x0A2020", "xor ebx, 0x20", "nop", "mov ecx, ebx", "inc eax", "inc ebx", "nop", "nop"])
#logic_replacement(["mov ah, 0x0A", "nop", "inc eax", "nop"])


#The main function for this file, get it to check if the instruction has a bad char, if so, it will certainly be changed, also adjust for xor instructions as well,
#If the instruction is xor, then be sure that xor_replacement is called

    #For each marked target, get the number on the right if there is one, then get generate an xor pair, xor it with the first and replace the number, then add an xor instruction immediately after or before the register is used again or a call or jump