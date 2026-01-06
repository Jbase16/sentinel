
import sys
import os
import shutil
from tabulate import tabulate
from colorama import Fore, Style, init

# Ensure core is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from core.toolkit.registry import TOOLS, get_tool_command, find_binary, COMMON_WORDLIST

init(autoreset=True)

def verify_registry():
    print(f"{Fore.CYAN}Verifying Tool Registry ({len(TOOLS)} tools)...{Style.RESET_ALL}\n")
    
    headers = ["Tool", "Type", "Binary Path", "Arg Gen", "Status"]
    rows = []
    
    success_count = 0
    
    sorted_tools = sorted(TOOLS.items(), key=lambda x: x[0])
    
    for name, tool in sorted_tools:
        status = f"{Fore.GREEN}OK{Style.RESET_ALL}"
        
        # 1. Binary Check
        binary_name = tool.binary_name or tool.cmd_template[0]
        path = find_binary(binary_name)
        
        path_display = f"{Fore.GREEN}{path}{Style.RESET_ALL}" if path else f"{Fore.RED}MISSING{Style.RESET_ALL}"
        if not path:
            status = f"{Fore.RED}FAIL (Bin){Style.RESET_ALL}"
        
        # 2. Argument Generation Check
        arg_status = f"{Fore.GREEN}OK{Style.RESET_ALL}"
        cmd_str = ""
        try:
            cmd, stdin = get_tool_command(name, "example.com")
            cmd_str = " ".join(cmd)
            
            # Specific checks for wordlist tools
            if name in ["dirsearch", "gobuster", "feroxbuster", "wfuzz"]:
                if COMMON_WORDLIST not in cmd and str(COMMON_WORDLIST) not in cmd:
                     arg_status = f"{Fore.RED}NO WORDLIST{Style.RESET_ALL}"
                     status = f"{Fore.RED}FAIL (Args){Style.RESET_ALL}"
                     
            if stdin:
                arg_status += " (Stdin)"
                
        except Exception as e:
            arg_status = f"{Fore.RED}ERROR: {e}{Style.RESET_ALL}"
            status = f"{Fore.RED}FAIL (Gen){Style.RESET_ALL}"
            
        rows.append([name, tool.target_type, path_display, arg_status, status])
        
        if "FAIL" not in status:
            success_count += 1

    print(tabulate(rows, headers=headers, tablefmt="grid"))
    
    print(f"\n{Fore.CYAN}Summary: {success_count}/{len(TOOLS)} tools valid.{Style.RESET_ALL}")
    
    if success_count < len(TOOLS):
        sys.exit(1)

if __name__ == "__main__":
    verify_registry()
