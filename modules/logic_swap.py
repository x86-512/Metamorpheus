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

#@debughook_verbose
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
    returnable:list = [updated_instruction,xor_pair[1], "xor"] 
    return returnable

#@debughook_verbose
def add_replacement_suggestion(instruction:str) -> list:
    #print("ADD REPLACEMENT CALL")
    if "0xff" in instruction.lower():
        return xor_replacement_suggestion(instruction)
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
#@debughook_verbose
def sub_replacement_suggestion(instruction:str) -> list:
    mnemonic = instruction.split(" ")[0]
    target_mnemonic = mnemonic
    if mnemonic=="mov" or mnemonic=="xor":
        target_mnemonic = "sub"
    if mnemonic=="sub":
        target_mnemonic = "add"
    target_num = instruction.split(", ")[1]
    arch = get_register_size(instruction)
    if "0xff" in instruction.lower():
        return xor_replacement_suggestion(instruction)
    if arch==64 and len(unbeautify_hex(target_num))<=10:
        arch=32 #Treat it as 32-bit
    elif arch==64 and len(unbeautify_hex(target_num))>10:
        return [instruction, "0x00000000"]
    sub_pair = random_hex_sub_pair(target_num, arch)
    updated_instruction = instruction.replace(target_num, sub_pair[0])
    returnable:list = [updated_instruction,sub_pair[1], target_mnemonic] 
    return returnable

#def push_change(instructions):
#    for i, instruction in enumerate(instructions):
#        if 'push' in instruction.lower():

#If something has to wrap around, just turn it into a xor
#ALso check to verify that the replacement suggestions don't get updated
#If and only if xor, you may repeat the logic swap
#Will be rewritten
def logic_replacement(self, instructions:list) -> list:
    bad_math_instructions = []
    math_instructions = []
    random_add_limit = calculate_change_limit(len(instructions))
    random_adds = 0
    do_not_change = []
    previously_added:int = 0
    no_more_updates = []
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

        insplit = instruction.split(' ')
        #Test
        if "push" in insplit[0].lower() and "0x" in insplit[1].lower() and len(insplit[1])==10:
            replacements = random_hex_xor_pair(insplit[1], 32)
            instructions[i] = insplit[0]+f" {replacements[0]}"
            stack_pointer = "rsp" if self.is_64 else "esp"
            self.insertWithCare(instructions, f"xor dword ptr [{stack_pointer}], {replacements[1]}", i+1, False)
            add_to_int_list(no_more_updates, len(no_more_updates), i)
            add_to_int_list(no_more_updates, len(no_more_updates), i+1)

            add_to_int_list(do_not_change, len(do_not_change), i)
            add_to_int_list(do_not_change, len(do_not_change), i+1)
            # if "cmp" in insplit[0].lower() and "0x" in insplit[-1] and len(insplit[-1])==10:
            #operand_size = 64 if self.is_64 else 32
            #operand = instruction[instruction.find(' '):instruction.find(',')]
            #if 'byte' in operand or (len(operand)==2 and ('l' in operand or 'h' in operand)): 
            #    operand_size=8
            #elif 'word' in operand or (len(operand)==2 and 'x' in operand): 
            #    operand_size=16
            #elif 'dword' in operand or (len(operand)==3 and 'e' in operand[0]): 
            #    operand_size=32
            #elif 'qword' in operand or (len(operand)==3 and 'r' in operand[0]): 
            #    operand_size=64
            #cmp_pair = random_hex_xor_pair(insplit[-1], operand_size) #get the operand_size
            #instructions[i]=instruction[:instruction.find(',')]+f", {cmp_pair[0]}"
            #self.insertWithCare(instructions, f"xor {operand}, {cmp_pair[1]}", i+2, False)
            #self.insertWithCare(instructions, f"xor {operand}, {cmp_pair[1]}", i, False, True)

            #add_to_int_list(no_more_updates, len(no_more_updates), i)
            #add_to_int_list(no_more_updates, len(no_more_updates), i+1)
            #add_to_int_list(no_more_updates, len(no_more_updates), i+2)

            #add_to_int_list(do_not_change, len(do_not_change), i)
            #add_to_int_list(do_not_change, len(do_not_change), i+1)
            #add_to_int_list(do_not_change, len(do_not_change), i+2)
            #.find(space) to find(,)
            #Generate a random xor pair, add xor before the cmp(if cmp is a jump target, the jump target will stay the same)
            #Add xor after and before the jump


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
            if instruction.split(" ")[0]==j and instruction.split(', ')[1][0:2]=="0x": #Test for dereferences
                insert_index = 0
                if contains_bad_chars(beautify_hex(instruction.split(', ')[1], instruction_size)):
                    targetMnemonic = mnemonic
                    match mnemonic:
                        case "mov":
                            replacement_suggestions = xor_replacement_suggestion(instruction)
                            targetMnemonic = "xor"
                        #case "xor":
                        #    replacement_suggestions = xor_replacement_suggestion(instruction)
                        #    targetMnemonic = "xor"
                        #breaks when add 0xff followed by a bad char
                        #Add something and then xor it
                    if replacement_suggestions[1]=="0x00000000":
                        continue
                    instructions[i] = replacement_suggestions[0]
                    register = unsplit_string(instruction.split(",")[0].split(" ")[1:], " ") #But what is there's a dereference?
                    max_reg:int = i+1
                    max_reg_possibles:list[int] = []
                    for k, after_instr in enumerate(instructions[i+1:], start=i+1): #Also check if it is register dependent
                        #print(k)
                        #print(after_instr)
                        for sub in registerClassMain(register):
                            if sub in after_instr:
                                max_reg_possibles.append(k)
                        for crit in critical_instrs:
                            if crit in after_instr:
                                max_reg_possibles.append(k)
                        #if 'push' in after_instr.lower() or 'pop' in after_instr.lower():
                        #     max_reg_possibles.append(k)
                        if register.lower() in after_instr.lower():
                            max_reg_possibles.append(k)
                        for target in self.jumpTargets:
                            #print(f"Target: {target}")
                            if k==target:
                            #if(sub in l or after_instr.split(" ")[0]==crit or k==target): #CHECK THE ENTIRE REGISTER CLASS, ALSO CHECK REG-Dependent instryctuib
                                #CHECK IT TO MAKE SURE IT IS BEFORE A JUMP_TARGET
                                max_reg_possibles.append(k)
                    if len(max_reg_possibles)>0:
                        max_reg = min(max_reg_possibles)
                    insert_index = random.randint(i+1, max_reg)
                    #print(f"Target_mnemonic: {targetMnemonic}")
                    self.insertWithCare(instructions, f"{targetMnemonic} {register}, {replacement_suggestions[1]}", insert_index, False)
                elif random_adds<random_add_limit and i not in no_more_updates:
                    rand_max = random.randint(3,5)
                    change_to_change = random.randint(0,rand_max+4)

                    #update to only apply probability to xor, logic replacement for add and sub should only occur once, add to a list of indexes and update if anything is updated before an index 
                    if True:#change_to_change<rand_max:#random.randint(0,rand_max-1):
                        targetMnemonic = mnemonic
                        replacement_suggestions = [-1,-1,-1]
                        match mnemonic:
                            case "mov":
                                replacement_suggestions = xor_replacement_suggestion(instruction)
                                targetMnemonic = "xor"
                            #case "xor":
                            #    replacement_suggestions = xor_replacement_suggestion(instruction)
                            #    target_mnemonic = "xor"
                            
                        if replacement_suggestions==[-1,-1,-1]:
                            continue
                        if replacement_suggestions[1]=="0x00000000":
                            continue
                        instructions[i] = replacement_suggestions[0]
                        register = unsplit_string(instruction.split(",")[0].split(" ")[1:], " ") #But what is there's a dereference?
                        max_reg:int = i+1
                        max_reg_possibles:list[int] = []
                        for k, after_instr in enumerate(instructions[i+1:], start=i+1): #Also check if it is register dependent
                            #print(k)
                            #print(after_instr)
                            for sub in registerClassMain(register):
                                #print(sub)
                                if sub in after_instr:
                                    max_reg_possibles.append(k)
                                    break
                            for crit in critical_instrs:
                                #print(crit)
                                if crit in after_instr:
                                    max_reg_possibles.append(k)
                                    break
                            for target in self.jumpTargets:
                                #print(f"Target: {target}")
                                if k==target:
                                #if(sub in l or after_instr.split(" ")[0]==crit or k==target): #CHECK THE ENTIRE REGISTER CLASS, ALSO CHECK REG-Dependent instryctuib
                                    #CHECK IT TO MAKE SURE IT IS BEFORE A JUMP_TARGET
                                    max_reg_possibles.append(k)
                                    break
                        if len(max_reg_possibles)>0:
                            max_reg = min(max_reg_possibles)
                        #print(max_reg)
                        try:
                            insert_index = random.randint(i+1, max_reg)
                        except ValueError:
                            insert_index = i+1

                        self.insertWithCare(instructions, f"{targetMnemonic} {register}, {replacement_suggestions[1]}", insert_index, False)
                        #if 'xor' not in targetMnemonic.lower():
                        random_adds+=1
    

                add_to_int_list(no_more_updates, len(no_more_updates), i)
                add_to_int_list(no_more_updates, len(no_more_updates), insert_index)
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
