import os

def copy_template(template_file:str):
    if os.name != "nt":
        os.system(f"cp templates/{template_file} template-temp.c")
    pass

def add_to_string(split_list, unsplit:str, index:int, to_add:str) -> str:
    returnable = ""
    for i, split in enumerate(split_list):
        if split!=split_list[-1]:
            if i==index:
                returnable+=split+to_add+"\""
            else:
                returnable+=split+"\""
        else:
            if i==index:
                returnable+=split+to_add
            else:
                returnable+=split
    return returnable
