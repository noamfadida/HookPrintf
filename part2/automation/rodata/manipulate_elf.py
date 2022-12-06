import os
import argparse
import lief

CURR_DIR = os.path.dirname(__file__)
DEFAULT_ORIG_STR = "Hello World"
OUTPUT_ELF_NAME = "elf_hacked"

def print_error(msg:str) -> None:
    """ Print error message in red color"""
    print(f"\033[91m{msg}\033[00m")

def print_success(msg: str) -> None:
    """ Print success message in green color"""
    print(f"\033[92m{msg}\033[00m")

def substitute_string(elf_name: str, orig_str: str, malicious_str: str) -> None:
    """
    Read the given ELF file, and sustitute an exisiting string with 
    malicious string, by rewriting to the .rodata section. 
    The output ELF file will be saved to the current folder, named "elf hacked".
    Remember to run chmod +x to the output file in order to succesfully run it.
    
    Parameters
    ----------
    elf_name: str
        Name of the HelloWorld ELF program to be injected. 
        This ELF should be located in the same folder of this script.
    orig_str: str
        The string that printf prints, and we want to substitue.
    malicious_str: str
        The new malicious string we want the program to print.
    """

    binary: lief.ELF.Binary = lief.parse(f"{CURR_DIR}/{elf_name}")
    if binary is None:
        print_error(f"ELF {elf_name} file doesn't exist in the current directory!")
        return
    rodata : lief.ELF.Section = binary.get_section(".rodata")
    rodata_base_VA: int = rodata.virtual_address
    content: memoryview = rodata.content
    content_str: str = bytes(content).decode()
    initial_index = content_str.find(orig_str)
    if initial_index == -1:
        print_error(f"String {orig_str} doesn't exist in the given ELF!")
        return
    malicious_content_str: str = content_str[0: initial_index] + malicious_str
    malicious_bytes_arr: bytearray = bytearray(malicious_content_str, 'ASCII')
    malicious_bytes_arr.append(0)
    binary.patch_address(rodata_base_VA, malicious_bytes_arr)
    binary.write(f"{CURR_DIR}/{OUTPUT_ELF_NAME}")
    print_success(f"File successfuly hacked! see {OUTPUT_ELF_NAME} ;)")


def main():
    parser = argparse.ArgumentParser(description='Hack HelloWorld program')
    parser.add_argument('--elf', '-e', type=str, default="hello_world", 
                        help='HelloWorld program Elf name.')
    parser.add_argument('--origstr', '-s', type=str, default=DEFAULT_ORIG_STR,
                        help='HelloWorld string to subsitute. Default is "Hello World".')
    parser.add_argument('--malicious', '-m', type=str, 
                        help='Malicious string to substitute with HelloWorld string.')
    args = parser.parse_args()
    
    substitute_string(args.elf, args.origstr, args.malicious)


if __name__=="__main__":
    main()


