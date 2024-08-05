Metamorpheus is a metamorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions. For now, I have focused on adding static detection evasion mechanisms, but I might add dynamic detection evasion soon as well.

Metamorpheus is designed to work in a R-E memory region, so you can place obfuscated code into the .text section of a PE file. It also works on shellcode for exploits.

Feature List:
| Feature | Status |
| --- | --- |
| Useless Instructions | Working |
| Garbage Bytes | Working |
| Logic Replacement | Runtime Issues |
| Register Swap (Universal) | Limited Functionality |
| Register Swap (Subroutine) | Not finished |
| Encryption | Unimplemented due to AESDEC issues |

Note:
The Universal Register swap only works correctly on certain shellcodes. I recommend only using this on smaller shellcode with little to no subroutines or else your code will not run.

Known Bugs: 
- Logic Swap will not work as intended on metasploit shellcode. I am currently working on a fix.
- Register Swap does not check if a jmp is within the main subroutine or not, it may not work within encapsulated jumps.
