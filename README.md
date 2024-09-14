# Polymorpheus
__This project is undergoing rewrite to reduce overcomplexity and to simplify the process of adding new features__

Polymorpheus is a polymorphic/metamorphic shellcode obfuscator that is designed to evade signature-based antivirus solutions and payload-based IPS Systems. Shellcode generated with this script is also capable of bypassing basic dynamic detection. If you are having a disassembly error, please check for any instructions labeled `(bad)` in https://defuse.ca/online-x86-assembler.htm.

Polymorpheus is designed to work in a W^E memory region (you can either write or execute, but not both), so you can place obfuscated code into the .text section of a PE file. It also works on shellcode for exploits.

# How to run
1. Install Dependencies
2. Make a file, `shellcode.txt` (case sensitive), with the architecture on the first line and the shellcode on the second line
3. Run main.py by its correct syntax, `python3 main.py -(arguments)`

# Features
| Feature | Description |
| --- | --- |
| Anti Debug | Checks the trap flag. If it is 1, the program crashes. |
| Garbage Bytes | Adds random bytes to shift the disassembler's perceived instruction locations. |
| Logic Replacement | Changes constants in the program for mov instructions. |
| Long Sleep | Adds a long loop before the shellcode executes. |
| Useless Instructions | Adds useless instructions that have no impact on how the shellcode is run. |

These features often involve adding instructions to existing shellcode. Therefore, all subroutine-related instructions are updated correctly with regards to what was added. This will take in to account whether a call is inside or outside of the shellcode and what is between the jump and its target.

# Dependencies
- Python: At least 3.10
- Pip: At least 22.0.0
- [Library] keystone-engine: At least 0.9.0
- [Library] capstone: At least 5.0.0

Open a terminal in the polymorpheus directory and type: `pip install -r requirements.txt`
