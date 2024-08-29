# Polymorpheus
__This project is undergoing rewrite to reduce overcomplexity and add support for new features__

Polymorpheus is a polymorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions and payload-based IPS Systems. For now, I have focused on adding static detection evasion mechanisms, but I might add dynamic detection evasion soon as well.

Polymorpheus is designed to work in a R-E memory region, so you can place obfuscated code into the .text section of a PE file. It also works on shellcode for exploits.

Feature List:
| Feature | Description |
| --- | --- |
| Useless Instructions | Adds useless instructions that have no impact on how the shellcode is run |
| Garbage Bytes | Adds random bytes to shift the disassembler's perceieved instruction locations |
| Logic Replacement | Changes constants in the program for mov, add, and sub instructions. (push and pop will be added soon) |

These features often involve adding instructions to existing shellcode. Therefore, all subroutine-related instructions are updated correctly with regards to what was added. This will take in to account whether a call is inside or outside of the shellcode and what is between the jump and its target.
