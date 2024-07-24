Metamorphia is a metamorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions. Due to the complexity of the project, only a few features have been added, but I plan on adding more.

Known Bugs: 
- Register Swap does not check if a jmp is within the main subroutine or not, it may not work within encapsulated jumps.
