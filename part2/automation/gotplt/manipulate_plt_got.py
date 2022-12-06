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

def substitute_string(elf_name: str) -> None:
    """
    Read the given ELF file, and sustitute an exisiting string with 
    malicious string, by patching the .got section. 
    The output ELF file will be saved to the current folder, named "elf_got_hacked".
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
    fake_printf: lief.ELF.Binary = lief.parse("fake_printf")
    
    segment_added = binary.add(fake_printf.segments[0])
    fake_printf_sym = fake_printf.get_symbol("fake_printf")
    fake_printf_addr = segment_added.virtual_address + fake_printf_sym.value

    binary.patch_pltgot('printf', fake_printf_addr)

    binary.write('hello_world.hookpltgot')

def main():
    parser = argparse.ArgumentParser(description='Hack HelloWorld program')
    parser.add_argument('--elf', '-e', type=str, default="hello_world", 
                        help='HelloWorld program Elf name.')
    args = parser.parse_args()
    
    substitute_string(args.elf)


if __name__=="__main__":
    main()


