from capstone import *
from keystone import *
import random
from essentials import * 
#add instructions for installing


jumpInstructions = ["jmp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "call", "loop", "loope", "loopne", "loopnz", "loopz"]#Add other instructions and move to main



#Global
#takenRegisters = []

def randomizeMappingMain(self, register:str, instructions) -> int:
    initReg = mapRegisterToNumber(register)
    oldReg = int(initReg/10)*10#Check against taken ones, if taken, generate a new one and check again
    nowTaken = random.randint(1,5)*10
    while(True):
        equals=0
        for taken in self.takenRegisters:
            if (nowTaken!=taken):
                equals += 1
        if(equals==len(takenRegisters)):
            self.takenRegisters.append(nowTaken)
            break
        else:
            nowtaken = random.randint(1,5)*10
    return abs(nowTaken-oldReg)


def mapRegisters(classes:list) -> list:#Create a randomized map for register swapping
    array = []
    debug = []
    for i in classes:
        mapped = False
        while mapped ==False:
            randomAdd = 50-random.randint(1,4)*10
            if(len(array)==0):
                a=mapRegisterToNumber(i)
                a = a - a%10 # A is the original class
                array.append(randomAdd-(a))#Add offset
                mapped = True
                debug.append(mapNumberToRegister(randomAdd))
            else:
                randomAdd = 50-random.randint(1,4)*10
                a=mapRegisterToNumber(i)
                a = a - a%10
                while True:
                    randomAdd = 50 - random.randint(1,4)*10
                    counter = 0
                    for j in debug:
                        newRegister = mapNumberToRegister(randomAdd)
                        if(j==newRegister):#It's repeating registers, the offsets are being compared, not the registers, array[j]
                            counter += 1
                    if counter == 0:
                        break
                array.append(randomAdd-(a))#Add the offset
                debug.append(mapNumberToRegister(randomAdd))
                mapped = True
    return array


def offsetToRegister(self, register:str, offset:list): #Add to object
    if self.is_64:
        defaultList = ["rax", "rcx", "rdx", "rbx"]
    else:
        defaultList = ["eax", "ecx", "edx", "ebx"]
    for i in range(len(defaultList)):
        regi = defaultList[i]
        if mapNumberToRegister(offset[i]+ mapRegisterToNumber(regi))==register:
            return regi
    return "null" 

                #Find reverse mapping by going through each in map and seeing if the 10's digit of the target matches to reg, then subtracting by that offset
def reverse_offset(register:str, offset_map:list) -> int:
    returnable = 0
    for i, map_off in enumerate(offset_map):
        base_class_num = (i+1)*10
        if(int(mapRegisterToNumber(base_class_num+map_off)/10)==int(mapRegisterToNumber(register)/10)):
            returnable = -map_off
    return returnable

def reverse_offset_replace(register:str, offset_map:list) -> str:
    print(register)
    returnable = ""
    for i, map_off in enumerate(offset_map):
        base_class_num = (i+1)*10
        print("\n")
        print(mapRegisterToNumber(base_class_num))
        print(f"Base Class: {int((base_class_num+map_off)/10)}")
        print(f"Class of reg: {int(mapRegisterToNumber(register)/10)}")
        if(int((base_class_num+map_off)/10)==int(mapRegisterToNumber(register)/10)):
            returnable = mapNumberToRegister(mapRegisterToNumber(register)-map_off)
            print("A\n\n")
    print(returnable)
    breakpoint()
    return returnable

#Check if jump is within subroutine, if not add it
def check_jump(self, instructions:list[str], jump_index:int) -> bool:
    jump_instr:str = instructions[jump_index]
    jump_len = int(jump_instr.split(" ")[1], 16)
    new_diff:int = 0
    if jump_len>0:
        for i, instr in enumerate(instructions[jump_index+1:], start=jump_index+1):
            if self.is_64:
                new_diff+=len(Shellcode.assemble64(instructions))
            else:
                new_diff+=len(Shellcode.assemble(instructions))
#Get an index where all 4 registers are used, if it is inside of a loop, then 

#Only swap once all of the 4 main registers are used
def registerSwap(self, instructions:list, start_ind_list = 0, end_ind_list = -1) -> list:
    #global jumpAddition
    if start_ind_list<0 or start_ind_list>=len(instructions):
        start_ind_list = 0
    if end_ind_list<0 or end_ind_list>=len(instructions) or end_ind_list>start_ind_list:
        end_ind_list = len(instructions)-1
    
    if self.is_64:
        registerClasses:list = ["rax", "rcx", "rdx", "rbx"]
    else:
        registerClasses:list = ["eax", "ecx", "edx", "ebx"]
    fullRegisterList = []
    for i in registerClasses:
        fullRegisterList.append(registerClassMain(i))
    #print(fullRegisterList)
    #breakpoint()
    registerMap = mapRegisters(registerClasses)

    if self.is_64:
        simulatedClasses = ["rax", "rcx", "rdx", "rbx"] #Update to account for 64 bit, directly changing it is hard
    else:
        simulatedClasses = ["eax", "ecx", "edx", "ebx"] #Update to account for 64 bit, directly changing it is hard

    markedInstructionsLeft = []
    markedInstructionsLeft_loc = start_ind_list
    markedInstructionsRight = []
    markedInstructionsRight_loc = end_ind_list
    counter = 0
    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
        for trails in range(len(simulatedClasses)):#Check the remainder of elements in the list
            if simulatedClasses[trails]==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                temp = simulatedClasses[trails]
                rando = random.randint(0,1)
                printIfEqual = random.randint(0,1)
                randoRight = random.randint(0,1)
                insertRight = True

                regOne = "" #Update so that for 64 bit, don't do the nop thing
                regTwo = ""
                if self.is_64:
                    regOne = simulatedClasses[r].replace('e', 'r')
                    regTwo = temp.replace('e', 'r')
                else:
                    regOne = simulatedClasses[r]
                    regTwo = temp
                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                    randomNoneRight = random.randint(0,1)
                    if randomNoneRight:
                        insertRight = False
                    counter -= 1
                elif rando: #Add replace instructiuons
                    markedInstructionsLeft.append(f"xchg {regOne}, {regTwo}")
                else:
                    markedInstructionsLeft.append(f"xchg {regTwo}, {regOne}")
                if randoRight and insertRight:#Get locations for right
                    markedInstructionsRight.append(f"xchg {regOne}, {regTwo}")
                elif insertRight and not randoRight:
                    markedInstructionsRight.append(f"xchg {regTwo}, {regOne}")
                simulatedClasses[trails] = simulatedClasses[r]
                simulatedClasses[r] = temp
        counter += 1
    if start_ind_list!=0 or end_ind_list!=len(instructions)-1:
        for i, mi in enumerate(markedInstructionsLeft):
            self.insertWithCare(instructions, mi, markedInstructionsLeft_loc, False)
            end_ind_list += 1
        for i, mi in enumerate(markedInstructionsRight):
            self.insertWithCare(instructions, mi, end_ind_list+1, False)
    locationMap = []
    newInstructions = []

    xchg_block_start = []
    xchg_block_end = []

    newInstructions = instructions
    for i, letter in enumerate(fullRegisterList):#Make it append to an array for each, regardless of whether something was found, so instead of foreach loops, it's for i in range()
        locationMap.append([])
        for j, letter_s in enumerate(letter):#a, c, d, b
            locationMap[i].append([])#al, eax, etc
            for k, instruction in enumerate(instructions[start_ind_list:end_ind_list+1]):#, start=start_ind_list):
                locationMap[i][j].append([])
                locationMap[i][j][k].append(findall(instruction,letter_s))
    markedInstructions = []
    markedInstructionsXchg = []
    #Key: Left: insertion location Right: register (o=all);   
    # 
    # 
    # IF CALLING REGISTER, RESWAP TO THE OLD REGISTER IF IT WAS PREVIOUSLY CHANGED
    notableInstructions = {#check call to see if it is in range of shellcode, if not treat it like jmp
        "ret": "ao", #la
        "int": "ao",
        "syscall": "ao",
        "loop": "jo",#Update for loops and jecxz/jcxz, and add correct register swap locations with ergards to target
        "jecxz 0x": "jo", #Could jump to arbitraty memory location, check if it is within range or not
        "jcxz 0x": "jo",
        "jecxz": "ao",#out of shellcode so treat as syscall
        "jcxz": "ao",#out of shellcode
        "call": "ao",#Check for 0x and relative locations, if so, skip
        "call 0x": "jo",#Check for 0x and relative locations, if so, skip
        "pusha": "ao",
        "popa": "ao",
        "cdq": "ao", #aad
        "cwd": "ao", #aad
        "div": "ao",
        "idiv": "ao",
        "lodsb": "ao"
        #Check other register dependent instructions
        #Change for near jumps/callss
    }
    #when  i
    #For 64 bit, if the call target is within the function, swap the registers back, then at the end, swap it back and swap it back after the call
    


    for i, jumpIndex in enumerate(self.jumpIndexes):
        jumpSnapshots.append(instructions[jumpIndex:self.jumpTargets[i]])
    notableInstructionsList = []
    notableXchgMapList = []
    for i in notableInstructions.keys():
        notableInstructionsList.append(i)
    for i in notableInstructions.values():
        notableXchgMapList.append(i)
    for i, instruction in enumerate(instructions[start_ind_list:end_ind_list+1], start=start_ind_list):
        for j in range(len(notableInstructionsList)):
            if instructions[i].find(notableInstructionsList[j])==0:#Add a dictionary with index:int and notableXchgMapList[j]
                #compare I to a jump index, if it is one, add its corresponding target to the jumpInstructionsTargets, when editing the targets, add the reverse first(that will not be jumped on)

                markedInstructions.append(i)
                markedInstructionsXchg.append(notableXchgMapList[j])
    for i, letter in enumerate(fullRegisterList):#Change it now
        for j, subregister in enumerate(letter):
            for k, instruction in enumerate(instructions[start_ind_list:end_ind_list+1], start=start_ind_list):#Check if multiple rets change len
                indexes = locationMap[i][j][k-start_ind_list][0]
                if not indexes:
                    continue
                else:
                    for index in indexes:
                        newNumber = mapRegisterToNumber(instruction[index:index+len(subregister)])+registerMap[i]
                        newRegister = mapNumberToRegister(newNumber)
                        update = replace(newInstructions[k], index, newRegister, index+len(subregister)) 
                        newInstructions[k] = update
    newInstructions = Shellcode.fixBadOperands(newInstructions, registerMap)    

    #Create a snapshot of changes and each time it is modified,
    markedInstructionsAdditions = []
    markedInstructionsAdditionsRight = []
    markedInstructionsAdditionsJump = []
    markedInstructionsLocations = []
    markedInstructionsTargets = []

    for loc in markedInstructions:
        try:
            if(instructions[loc][0:4]=="loop"):
                indexOfJMP = self.jumpIndexes.index(loc)

                pass
                #Insert it at 
            #Check if it is a register, if so, change the register to what it should be
        except IndexError:
            print(f"Index error in {markedInstructions[loc]}")


    for loc in markedInstructions:
        try:
            #Check if it is a register, if so, change the register to what it should be
            for reg_class in fullRegisterList:
                found:bool = False
                #Find reverse mapping by going through each in map and seeing if the 10's digit of the target matches to reg, then subtracting by that offset
                for reg in reg_class:
                    try:
                        index_of_reg = findall(newInstructions[loc], reg)[0]
                        if(newInstructions[loc].split(" ")[1].find(reg)==0):
                            print(f"New: {newInstructions}")
                            print(f"New: {newInstructions[loc]}")
                            new_reg = reverse_offset_replace(reg, registerMap)
                            newInstructions[loc] = replace(newInstructions[loc], index_of_reg, new_reg, index_of_reg+len(reg))
                            #pass
                            found = True
                            break
                            #Figure out how to re-add that in the function
                    except IndexError:
                        pass
                if found:
                    break
        except IndexError:
            print(f"Index error in {markedInstructions[loc]}")

    print(newInstructions)
    for i, locationInd in enumerate(markedInstructions):#Remember to get lengths and indexes and then add them to jmp instructions
        #For jmp instructions, find if added instructions are between jmp and its target, add the bytes of inserted code into the jmp statement
        locyyy = newInstructions[markedInstructions[i]]
        locationRelative = markedInstructionsXchg[i][0]
        registersToSwap = markedInstructionsXchg[i][1:]

#When instruction is inserted, add to table the length of what was added

        markedInstructionsAdditions.append([])
        markedInstructionsAdditionsRight.append([])
        markedInstructionsAdditionsJump.append([])
        markedInstructionsTargets.append([])
        #print(registersToSwap)
        for j in range(len(registersToSwap)):
            #print(j)
            if self.is_64:
                simulatedClasses = ["rax", "rcx", "rdx", "rbx"] #Update to account for 64 bit, directly changing it is hard
            else:
                simulatedClasses = ["eax", "ecx", "edx", "ebx"] #Update to account for 64 bit, directly changing it is hard
            if registersToSwap[j] == 'o':
                if locationRelative=="l":
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            #Check if target register == desired(i.e. ecx and eax were swapped with 10 -10

                            if temp==registerClasses[r+int(registerMap[r]/10)]:
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                if not printIfEqual and temp==simulatedClasses[r]:#Either insert dead code or just skip
                                    counter -= 1
                                elif rando:
                                    self.insertWithCare(newInstructions, f"xchg {temp}, {simulatedClasses[r]}", locationInd+counter, False)
                                else:
                                    self.insertWithCare(newInstructions, f"xchg {simulatedClasses[r]}, {temp}", locationInd+counter, False)
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp

                        counter += 1

                elif locationRelative=="r":#Redo
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            #Check if target register == desired(i.e. ecx and eax were swapped with 10 -10

                            if temp==registerClasses[r+int(registerMap[r]/10)]:
                                #print(r+int(registerMap[r]/10)) #Works as expected
                                rando = random.randint(0,1)
                                #print(temp)
                                printIfEqual = random.randint(0,1)
                                if not printIfEqual and temp==simulatedClasses[r]:#Either insert dead code or just skip
                                    counter -= 1
                                elif rando:

                                    self.insertWithCare(newInstructions, f"xchg {temp}, {simulatedClasses[r]}", locationInd+counter+1, False)

                                else:
                                
                                    self.insertWithCare(newInstructions, f"xchg {simulatedClasses[r]}, {temp}", locationInd+counter+1, False)
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp

                        counter += 1
                elif locationRelative=="a":
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                insertRight = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                #print(f"\n\n\n\n\n\n\n\n\n\n{self.is_64}")
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
                elif locationRelative=="j": #start working
                    #IMPROVE FOR 64 BIT AND jecxz
                    counter = 0
                    try:
                        indexOfJMP = self.jumpIndexes.index(locationInd)
                        markedInstructionsTargets[i] = (self.jumpTargets[indexOfJMP])
                    except IndexError:
                        
                        print("JUMP INDEX ERROR")
                        pass
                    for r, register in enumerate(registerClasses):
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                randoJmp = random.randint(0,1)
                                insertRight = True
                                insertJmp = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                if randoJmp and insertJmp:#Get locations for right
                                    markedInstructionsAdditionsJump[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertJmp and not randoJmp:
                                    markedInstructionsAdditionsJump[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
            elif locationRelative=="x": #start working
                    #IMPROVE FOR 64 BIT AND jecxz
                    #print("JUMP CHANGE")
                    counter = 0
                    for r, register in enumerate(registerClasses):
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                insertRight = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
            else:
                print("Invalid Jump")
    for i, locationInd in enumerate(markedInstructions):
        locationInd = markedInstructions[i]
        addToInstrs = 0
        jump_loop_insert = 0x0
        current_instruction_index = locationInd
        saved_instruction =  newInstructions[current_instruction_index]
        added_from_jump = 0
        jump_to_index = 0
        for j, added_left in enumerate(markedInstructionsAdditions[i]): #Update the additions indexes to account for the insertions
            self.insertWithCare(newInstructions, markedInstructionsAdditions[i][j], locationInd, False) #Removed +j
            current_instruction_index+=1
            for x, target in enumerate(markedInstructionsTargets):
                if isinstance(target, int) and locationInd<target:
                    markedInstructionsTargets[x]+=1 #Maybe account for what was inserted right
            locationInd+=1
            if j==0: #MOVE
                jump_to_index = markedInstructionsTargets[i]

            if isinstance(markedInstructionsTargets, int):
                if markedInstructionsTargets[i]<current_instruction_index:
                    locationInd+=1
                    markedInstructions[i]+=1
        for j, added_right in enumerate(markedInstructionsAdditions[i]): #Update the additions indexes to account for the insertions
            self.insertWithCare(newInstructions, markedInstructionsAdditionsRight[i][j], locationInd+1, False) #Error here where it inserts at wrong loc and fucks up the index
            current_instruction_index+=1
            #if inserted before, add
            for x, target in enumerate(markedInstructionsTargets):
                if isinstance(target, int) and locationInd<target:
                    markedInstructionsTargets[x]+=1 #Maybe account for what was inserted right
            if j==0: #MOVE
                jump_to_index = markedInstructionsTargets[i]

            if isinstance(markedInstructionsTargets, int):
                if markedInstructionsTargets[i]<current_instruction_index:
                    locationInd+=1
                    markedInstructions[i]+=1
        for j, added_instr in enumerate(markedInstructionsAdditionsJump[i]):
            if len(markedInstructionsAdditionsJump[i])>0:
                self.insertWithCare(newInstructions, markedInstructionsAdditionsJump[i][j], markedInstructionsTargets[i], False, True) #markedInstructionsTargets[i] needs to be updated
                if(markedInstructionsTargets[i]<current_instruction_index):
                    current_instruction_index+=1
                    markedInstructions[i]+=1
                    locationInd+=1
                    added_from_jump += 1
                    for x, instr_sub in enumerate(markedInstructions[i+1:]):
                        markedInstructions[x]+=1
                
                if self.is_64:
                    jump_loop_insert+=len(Shellcode.assemble64([markedInstructionsAdditionsJump[i][j]]))
                else:
                    jump_loop_insert+=len(Shellcode.assemble([markedInstructionsAdditionsJump[i][j]]))
        if(newInstructions[locationInd][0:4]=="loop"):
            #If it is, get its target and add an initial jmp over that target
            new_jump_index = jump_to_index
            new_jump_target = new_jump_index + added_from_jump
            self.add_jump(newInstructions, new_jump_index, new_jump_target)
            locationInd+=1
            self.jumpTargets[self.jumpIndexes.index(locationInd)]+=1
            #For every marked instruction that is after the new jump, add 1 to it
            #For some reason, goes 1 over
            for sec_index, sec_instr in enumerate(markedInstructions):
                if(markedInstructions[sec_index]>=new_jump_index):
                    markedInstructions[sec_index]+=1
        #ADD MARKED TO CHECK IF CURRENT INSTRUCTION IS A JUMP
        for j in range(i+1, len(markedInstructions)):#It is multiplying by the reamaining indexes
            for u in range(len(markedInstructionsAdditions[i])):
                #Check if jump
                markedInstructions[j]+=2
                addToInstrs+=2

            #VERIFY THAT IT WAS INSERTED BEFORE THE REMAINING NOTABLE INSTRUCTIONS BEFORE UPDATING,
            #TEST WITH FORWARD JMPS
            ######################
            for x in (markedInstructionsAdditionsJump[i]): #CAUSING AN ERROR, IT IS GETTING THROWN OFF SOMEWHERE, AFTER THE LOOP, THEY ARE OFF BY 1 OR 2
                markedInstructions[j]+=1
                addToInstrs+=1
            
    for i in range(len(self.jumpIndexes)):
        toJump = int(newInstructions[self.jumpIndexes[i]].split(" ")[1], 16)
        try:
            if len(self.jumpAddition[i])!=0: #Causing an issue
                for j in range(len(self.jumpAddition[i])):
                    toJump += self.jumpAddition[i][j]
        except IndexError:
            toJump += 0

    self.jumpIndexes = []
    print(f"Register Map: {registerMap}")
    return newInstructions

def registerSwapSubroutine(self, instructions:list, start_ind_list = 0, end_ind_list = -1) -> list:
    #global jumpAddition
    if start_ind_list<0 or start_ind_list>=len(instructions):
        start_ind_list = 0
    if end_ind_list<0 or end_ind_list>=len(instructions) or end_ind_list>start_ind_list:
        end_ind_list = len(instructions)-1
    
    if self.is_64:
        registerClasses:list = ["rax", "rcx", "rdx", "rbx"]
    else:
        registerClasses:list = ["eax", "ecx", "edx", "ebx"]
    fullRegisterList = []
    for i in registerClasses:
        fullRegisterList.append(registerClassMain(i))
    #print(fullRegisterList)
    #breakpoint()
    registerMap = mapRegisters(registerClasses)

    if self.is_64:
        simulatedClasses = ["rax", "rcx", "rdx", "rbx"] #Update to account for 64 bit, directly changing it is hard
    else:
        simulatedClasses = ["eax", "ecx", "edx", "ebx"] #Update to account for 64 bit, directly changing it is hard

    markedInstructionsLeft = []
    markedInstructionsLeft_loc = start_ind_list
    markedInstructionsRight = []
    markedInstructionsRight_loc = end_ind_list
    counter = 0
    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
        for trails in range(len(simulatedClasses)):#Check the remainder of elements in the list
            if simulatedClasses[trails]==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                temp = simulatedClasses[trails]
                rando = random.randint(0,1)
                printIfEqual = random.randint(0,1)
                randoRight = random.randint(0,1)
                insertRight = True

                regOne = "" #Update so that for 64 bit, don't do the nop thing
                regTwo = ""
                if self.is_64:
                    regOne = simulatedClasses[r].replace('e', 'r')
                    regTwo = temp.replace('e', 'r')
                else:
                    regOne = simulatedClasses[r]
                    regTwo = temp
                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                    randomNoneRight = random.randint(0,1)
                    if randomNoneRight:
                        insertRight = False
                    counter -= 1
                elif rando: #Add replace instructiuons
                    markedInstructionsLeft.append(f"xchg {regOne}, {regTwo}")
                else:
                    markedInstructionsLeft.append(f"xchg {regTwo}, {regOne}")
                if randoRight and insertRight:#Get locations for right
                    markedInstructionsRight.append(f"xchg {regOne}, {regTwo}")
                elif insertRight and not randoRight:
                    markedInstructionsRight.append(f"xchg {regTwo}, {regOne}")
                simulatedClasses[trails] = simulatedClasses[r]
                simulatedClasses[r] = temp
        counter += 1
    if start_ind_list!=0 or end_ind_list!=len(instructions)-1:
        for i, mi in enumerate(markedInstructionsLeft):
            self.insertWithCare(instructions, mi, markedInstructionsLeft_loc, False)
            end_ind_list += 1
        for i, mi in enumerate(markedInstructionsRight):
            self.insertWithCare(instructions, mi, end_ind_list+1, False)
    locationMap = []
    newInstructions = []

    xchg_block_start = []
    xchg_block_end = []

    newInstructions = instructions
    for i, letter in enumerate(fullRegisterList):#Make it append to an array for each, regardless of whether something was found, so instead of foreach loops, it's for i in range()
        locationMap.append([])
        for j, letter_s in enumerate(letter):#a, c, d, b
            locationMap[i].append([])#al, eax, etc
            for k, instruction in enumerate(instructions[start_ind_list:end_ind_list+1]):#, start=start_ind_list):
                locationMap[i][j].append([])
                locationMap[i][j][k].append(findall(instruction,letter_s))
    markedInstructions = []
    markedInstructionsXchg = []
    #Key: Left: insertion location Right: register (o=all);   
    # 
    # 
    # IF CALLING REGISTER, RESWAP TO THE OLD REGISTER IF IT WAS PREVIOUSLY CHANGED
    notableInstructions = {#check call to see if it is in range of shellcode, if not treat it like jmp
        "ret": "ao", #la
        "int": "ao",
        "syscall": "ao",
        "loop": "jo",#Update for loops and jecxz/jcxz, and add correct register swap locations with ergards to target
        "jecxz 0x": "jo", #Could jump to arbitraty memory location, check if it is within range or not
        "jcxz 0x": "jo",
        "jecxz": "ao",#out of shellcode so treat as syscall
        "jcxz": "ao",#out of shellcode
        "call": "ao",#Check for 0x and relative locations, if so, skip
        "call 0x": "jo",#Check for 0x and relative locations, if so, skip
        "pusha": "ao",
        "popa": "ao",
        "cdq": "ao", #aad
        "cwd": "ao", #aad
        "div": "ao",
        "idiv": "ao",
        "lodsb": "ao"
        #Check other register dependent instructions
        #Change for near jumps/callss
    }
    #when  i
    #For 64 bit, if the call target is within the function, swap the registers back, then at the end, swap it back and swap it back after the call
    


    for i, jumpIndex in enumerate(self.jumpIndexes):
        jumpSnapshots.append(instructions[jumpIndex:self.jumpTargets[i]])
    notableInstructionsList = []
    notableXchgMapList = []
    for i in notableInstructions.keys():
        notableInstructionsList.append(i)
    for i in notableInstructions.values():
        notableXchgMapList.append(i)
    for i, instruction in enumerate(instructions[start_ind_list:end_ind_list+1], start=start_ind_list):
        for j in range(len(notableInstructionsList)):
            if instructions[i].find(notableInstructionsList[j])==0:#Add a dictionary with index:int and notableXchgMapList[j]
                #compare I to a jump index, if it is one, add its corresponding target to the jumpInstructionsTargets, when editing the targets, add the reverse first(that will not be jumped on)

                markedInstructions.append(i)
                markedInstructionsXchg.append(notableXchgMapList[j])
    for i, letter in enumerate(fullRegisterList):#Change it now
        for j, subregister in enumerate(letter):
            for k, instruction in enumerate(instructions[start_ind_list:end_ind_list+1], start=start_ind_list):#Check if multiple rets change len
                indexes = locationMap[i][j][k-start_ind_list][0]
                if not indexes:
                    continue
                else:
                    for index in indexes:
                        newNumber = mapRegisterToNumber(instruction[index:index+len(subregister)])+registerMap[i]
                        newRegister = mapNumberToRegister(newNumber)
                        update = replace(newInstructions[k], index, newRegister, index+len(subregister)) 
                        newInstructions[k] = update
    newInstructions = Shellcode.fixBadOperands(newInstructions, registerMap)    

    #Create a snapshot of changes and each time it is modified,
    markedInstructionsAdditions = []
    markedInstructionsAdditionsRight = []
    markedInstructionsAdditionsJump = []
    markedInstructionsLocations = []
    markedInstructionsTargets = []

    for loc in markedInstructions:
        try:
            if(instructions[loc][0:4]=="loop"):
                indexOfJMP = self.jumpIndexes.index(loc)

                pass
                #Insert it at 
            #Check if it is a register, if so, change the register to what it should be
        except IndexError:
            print(f"Index error in {markedInstructions[loc]}")


    for loc in markedInstructions:
        try:
            #Check if it is a register, if so, change the register to what it should be
            for reg_class in fullRegisterList:
                found:bool = False
                #Find reverse mapping by going through each in map and seeing if the 10's digit of the target matches to reg, then subtracting by that offset
                for reg in reg_class:
                    try:
                        index_of_reg = findall(newInstructions[loc], reg)[0]
                        if(newInstructions[loc].split(" ")[1].find(reg)==0):
                            print(f"New: {newInstructions}")
                            print(f"New: {newInstructions[loc]}")
                            new_reg = reverse_offset_replace(reg, registerMap)
                            newInstructions[loc] = replace(newInstructions[loc], index_of_reg, new_reg, index_of_reg+len(reg))
                            #pass
                            found = True
                            break
                            #Figure out how to re-add that in the function
                    except IndexError:
                        pass
                if found:
                    break
        except IndexError:
            print(f"Index error in {markedInstructions[loc]}")

    print(newInstructions)
    for i, locationInd in enumerate(markedInstructions):#Remember to get lengths and indexes and then add them to jmp instructions
        #For jmp instructions, find if added instructions are between jmp and its target, add the bytes of inserted code into the jmp statement
        locyyy = newInstructions[markedInstructions[i]]
        locationRelative = markedInstructionsXchg[i][0]
        registersToSwap = markedInstructionsXchg[i][1:]

#When instruction is inserted, add to table the length of what was added

        markedInstructionsAdditions.append([])
        markedInstructionsAdditionsRight.append([])
        markedInstructionsAdditionsJump.append([])
        markedInstructionsTargets.append([])
        #print(registersToSwap)
        for j in range(len(registersToSwap)):
            #print(j)
            if self.is_64:
                simulatedClasses = ["rax", "rcx", "rdx", "rbx"] #Update to account for 64 bit, directly changing it is hard
            else:
                simulatedClasses = ["eax", "ecx", "edx", "ebx"] #Update to account for 64 bit, directly changing it is hard
            if registersToSwap[j] == 'o':
                if locationRelative=="l":
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            #Check if target register == desired(i.e. ecx and eax were swapped with 10 -10

                            if temp==registerClasses[r+int(registerMap[r]/10)]:
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                if not printIfEqual and temp==simulatedClasses[r]:#Either insert dead code or just skip
                                    counter -= 1
                                elif rando:
                                    self.insertWithCare(newInstructions, f"xchg {temp}, {simulatedClasses[r]}", locationInd+counter, False)
                                else:
                                    self.insertWithCare(newInstructions, f"xchg {simulatedClasses[r]}, {temp}", locationInd+counter, False)
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp

                        counter += 1

                elif locationRelative=="r":#Redo
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            #Check if target register == desired(i.e. ecx and eax were swapped with 10 -10

                            if temp==registerClasses[r+int(registerMap[r]/10)]:
                                #print(r+int(registerMap[r]/10)) #Works as expected
                                rando = random.randint(0,1)
                                #print(temp)
                                printIfEqual = random.randint(0,1)
                                if not printIfEqual and temp==simulatedClasses[r]:#Either insert dead code or just skip
                                    counter -= 1
                                elif rando:

                                    self.insertWithCare(newInstructions, f"xchg {temp}, {simulatedClasses[r]}", locationInd+counter+1, False)

                                else:
                                
                                    self.insertWithCare(newInstructions, f"xchg {simulatedClasses[r]}, {temp}", locationInd+counter+1, False)
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp

                        counter += 1
                elif locationRelative=="a":
                    counter = 0
                    for r, register in enumerate(registerClasses):#loop through each register class in order, but add a list of previous xchg instructions mapping to know the current values in each register
                        #Current Register Array, start off with [eax...] and end with
                        #Simulate xchg
                        
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                insertRight = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                #print(f"\n\n\n\n\n\n\n\n\n\n{self.is_64}")
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
                elif locationRelative=="j": #start working
                    #IMPROVE FOR 64 BIT AND jecxz
                    counter = 0
                    try:
                        indexOfJMP = self.jumpIndexes.index(locationInd)
                        markedInstructionsTargets[i] = (self.jumpTargets[indexOfJMP])
                    except IndexError:
                        
                        print("JUMP INDEX ERROR")
                        pass
                    for r, register in enumerate(registerClasses):
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                randoJmp = random.randint(0,1)
                                insertRight = True
                                insertJmp = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                if randoJmp and insertJmp:#Get locations for right
                                    markedInstructionsAdditionsJump[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertJmp and not randoJmp:
                                    markedInstructionsAdditionsJump[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
            elif locationRelative=="x": #start working
                    #IMPROVE FOR 64 BIT AND jecxz
                    #print("JUMP CHANGE")
                    counter = 0
                    for r, register in enumerate(registerClasses):
                        register = registerClasses[r]
                        for trails, temp in enumerate(simulatedClasses):#Check the remainder of elements in the list
                            if temp==registerClasses[r+int(registerMap[r]/10)]: #Well there's my problem
                                rando = random.randint(0,1)
                                printIfEqual = random.randint(0,1)
                                randoRight = random.randint(0,1)
                                insertRight = True

                                regOne = "" #Update so that for 64 bit, don't do the nop thing
                                regTwo = ""
                                if self.is_64:
                                    regOne = simulatedClasses[r].replace('e', 'r')
                                    regTwo = temp.replace('e', 'r')
                                else:
                                    regOne = simulatedClasses[r]
                                    regTwo = temp
                                if not printIfEqual and temp==simulatedClasses[r] and not self.is_64:#Either insert dead code or just skip
                                    #print("if not printIfEqual and temp==simulatedClasses[r] and not self.is_64")
                                    randomNoneRight = random.randint(0,1)
                                    if randomNoneRight:
                                        insertRight = False
                                    counter -= 1
                                elif rando: #Add replace instructiuons
                                    markedInstructionsAdditions[i].append(f"xchg {regOne}, {regTwo}")
                                    markedInstructionsLocations.append(locationInd)
                                else:
                                    markedInstructionsAdditions[i].append(f"xchg {regTwo}, {regOne}")
                                    markedInstructionsLocations.append(locationInd)
                                if randoRight and insertRight:#Get locations for right
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regOne}, {regTwo}")
                                elif insertRight and not randoRight:
                                    markedInstructionsAdditionsRight[i].append(f"xchg {regTwo}, {regOne}")
                                simulatedClasses[trails] = simulatedClasses[r]
                                simulatedClasses[r] = temp
                        counter += 1
            else:
                print("Invalid Jump")
    for i, locationInd in enumerate(markedInstructions):
        locationInd = markedInstructions[i]
        addToInstrs = 0
        jump_loop_insert = 0x0
        current_instruction_index = locationInd
        saved_instruction =  newInstructions[current_instruction_index]
        added_from_jump = 0
        jump_to_index = 0
        for j, added_left in enumerate(markedInstructionsAdditions[i]): #Update the additions indexes to account for the insertions
            self.insertWithCare(newInstructions, markedInstructionsAdditions[i][j], locationInd, False) #Removed +j
            current_instruction_index+=1
            for x, target in enumerate(markedInstructionsTargets):
                if isinstance(target, int) and locationInd<target:
                    markedInstructionsTargets[x]+=1 #Maybe account for what was inserted right
            locationInd+=1
            if j==0: #MOVE
                jump_to_index = markedInstructionsTargets[i]

            if isinstance(markedInstructionsTargets, int):
                if markedInstructionsTargets[i]<current_instruction_index:
                    locationInd+=1
                    markedInstructions[i]+=1
        for j, added_right in enumerate(markedInstructionsAdditions[i]): #Update the additions indexes to account for the insertions
            self.insertWithCare(newInstructions, markedInstructionsAdditionsRight[i][j], locationInd+1, False) #Error here where it inserts at wrong loc and fucks up the index
            current_instruction_index+=1
            #if inserted before, add
            for x, target in enumerate(markedInstructionsTargets):
                if isinstance(target, int) and locationInd<target:
                    markedInstructionsTargets[x]+=1 #Maybe account for what was inserted right
            if j==0: #MOVE
                jump_to_index = markedInstructionsTargets[i]

            if isinstance(markedInstructionsTargets, int):
                if markedInstructionsTargets[i]<current_instruction_index:
                    locationInd+=1
                    markedInstructions[i]+=1
        for j, added_instr in enumerate(markedInstructionsAdditionsJump[i]):
            if len(markedInstructionsAdditionsJump[i])>0:
                self.insertWithCare(newInstructions, markedInstructionsAdditionsJump[i][j], markedInstructionsTargets[i], False, True) #markedInstructionsTargets[i] needs to be updated
                if(markedInstructionsTargets[i]<current_instruction_index):
                    current_instruction_index+=1
                    markedInstructions[i]+=1
                    locationInd+=1
                    added_from_jump += 1
                    for x, instr_sub in enumerate(markedInstructions[i+1:]):
                        markedInstructions[x]+=1
                
                if self.is_64:
                    jump_loop_insert+=len(Shellcode.assemble64([markedInstructionsAdditionsJump[i][j]]))
                else:
                    jump_loop_insert+=len(Shellcode.assemble([markedInstructionsAdditionsJump[i][j]]))
        if(newInstructions[locationInd][0:4]=="loop"):
            #If it is, get its target and add an initial jmp over that target
            new_jump_index = jump_to_index
            new_jump_target = new_jump_index + added_from_jump
            self.add_jump(newInstructions, new_jump_index, new_jump_target)
            locationInd+=1
            self.jumpTargets[self.jumpIndexes.index(locationInd)]+=1
            #For every marked instruction that is after the new jump, add 1 to it
            #For some reason, goes 1 over
            for sec_index, sec_instr in enumerate(markedInstructions):
                if(markedInstructions[sec_index]>=new_jump_index):
                    markedInstructions[sec_index]+=1
        #ADD MARKED TO CHECK IF CURRENT INSTRUCTION IS A JUMP
        for j in range(i+1, len(markedInstructions)):#It is multiplying by the reamaining indexes
            for u in range(len(markedInstructionsAdditions[i])):
                #Check if jump
                markedInstructions[j]+=2
                addToInstrs+=2

            #VERIFY THAT IT WAS INSERTED BEFORE THE REMAINING NOTABLE INSTRUCTIONS BEFORE UPDATING,
            #TEST WITH FORWARD JMPS
            ######################
            for x in (markedInstructionsAdditionsJump[i]): #CAUSING AN ERROR, IT IS GETTING THROWN OFF SOMEWHERE, AFTER THE LOOP, THEY ARE OFF BY 1 OR 2
                markedInstructions[j]+=1
                addToInstrs+=1
            
    for i in range(len(self.jumpIndexes)):
        toJump = int(newInstructions[self.jumpIndexes[i]].split(" ")[1], 16)
        try:
            if len(self.jumpAddition[i])!=0: #Causing an issue
                for j in range(len(self.jumpAddition[i])):
                    toJump += self.jumpAddition[i][j]
        except IndexError:
            toJump += 0

    self.jumpIndexes = []
    print(f"Register Map: {registerMap}")
    return newInstructions

Shellcode.randomizeMappingMain = randomizeMappingMain
Shellcode.registerSwap = registerSwap
Shellcode.offsetToRegister = offsetToRegister
