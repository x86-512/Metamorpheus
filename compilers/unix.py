import os
from compilers.common import *

def compile(arch:int, shellcode:str):
    if os.name=="nt":
        print("Compiling with this script is not compatible with Windows.\nUpgrade to Linux!")
    copy_template("template-unix.c")
    code:str = ""
    with open("template-temp.c", 'r') as template:
        code = template.read()
    code = add_to_string(code.split('"'), "", 1, shellcode)
    with open("template-temp.c", 'w') as template:
        template.write(code)
    os.system(f"gcc -m{arch} -z execstack -o loader template-temp.c")
    os.system("rm template-temp.c")
