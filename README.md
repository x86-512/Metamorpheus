Metamorpheus is a metamorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions. For now, I have focused on adding static detection evasion mechanisms, but I might add dynamic detection evasion soon as well.

Known Bugs: 
- Register Swap does not check if a jmp is within the main subroutine or not, it may not work within encapsulated jumps.
