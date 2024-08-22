Polymorpheus is a polymorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions and payload-based IPS Systems. For now, I have focused on adding static detection evasion mechanisms, but I might add dynamic detection evasion soon as well.

Polymorpheus is designed to work in a R-E memory region, so you can place obfuscated code into the .text section of a PE file. It also works on shellcode for exploits.

Feature List:
| Feature | Description |
| --- | --- |
| Useless Instructions | Adds useless instructions into the shellcode that has no impact on how the shellcode is run |
| Garbage Bytes | Adds random bytes to shift the disassembler's perceieved instruction locations. |
| Logic Replacement | Changes constants in the program for mov, add, and sub instructions. (push and pop will be added soon) |
