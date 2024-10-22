import os
import subprocess
import logging
import pwd
import grp
import stat
import yara
import sys
import getpass

red = '\033[31m'
green = '\033[32m'
yellow = '\033[0;33m'
cyan = '\033[0;36m'
bold = '\033[1m'
reset = '\033[0m'

class Logger(logging.Logger):
    def __init__(self, name, level=logging.DEBUG):
        super(Logger, self).__init__(name, level)
        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(message)s')
        self.console_handler.setFormatter(formatter)
        self.addHandler(self.console_handler)

    def set_level(self, level):
        self.setLevel(level)
        self.console_handler.setLevel(level)

logging.setLoggerClass(Logger)

log = logging.getLogger(__name__)
log.set_level(logging.INFO)


def get_sudo_password():

    log.info(f"{cyan}{bold}Enter sudo password:\n{reset}")
    return getpass.getpass("> ")


def execute_command(command, sudo_password=None):

    if sudo_password:
        command = f"echo {sudo_password} | sudo -S {command}"
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        return output.decode('utf-8'), error.decode('utf-8')
    except OSError as e:
        return None, "OS error occurred: " + str(e)


def check_suid_bins():

    suid_bins = []
    for binary in os.listdir('/usr/bin'):
        binary_path = os.path.join('/usr/bin', binary)
        if os.path.isfile(binary_path):
            file_properties = check_suid_sgid(binary_path)
            if file_properties.get("SUID") or file_properties.get("SGID"):
                suid_bins.append({
                    "Binary": binary,
                    "Path": binary_path,
                    "SUID": file_properties.get("Owner") if file_properties.get("SUID") else None,
                    "SGID": file_properties.get("Group") if file_properties.get("SGID") else None
                })
                log.warning(f"Found binary {yellow}{bold}{binary}{reset}: {binary_path}")
    return suid_bins


def check_suid_sgid(file_path):

    try:
        file_stat = os.stat(file_path)
        mode = file_stat.st_mode
        is_suid = bool(mode & stat.S_ISUID)
        is_sgid = bool(mode & stat.S_ISGID)
        owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
        group_name = grp.getgrgid(file_stat.st_gid).gr_name
        return {"SUID": is_suid, "SGID": is_sgid, "Owner": owner_name, "Group": group_name}
    except FileNotFoundError:
        return {"Error": "File not found"}


def check_binaries_with_yara(rule_path, binaries, sudo_password):

    rules = yara.compile(filepath=rule_path)

    log.info(f"{cyan}{bold}The verification for each binary has begun...\n{reset}") 

    for binary_info in binaries:
        binary_path = binary_info['Path']
        if os.path.isfile(binary_path): 
            matches = rules.match(binary_path)
            if matches:
                log.info(f"{red}{bold}YARA matches for {binary_path}: {matches}") 
            else:
                log.info(f"{green}{bold}No matches found for {binary_path}.") 
        else:
            log.warning(f"{red}{bold}Skipping {binary_path}, not a file.{reset}")


def main():
    sudo_password = get_sudo_password() 
    print(f"{cyan}{bold}Searching for SUID/SGID binaries...\n{reset}")
    suid_binaries = check_suid_bins()
    if suid_binaries:
        print(f"{cyan}{bold}\nThe following binary files will be sent for verification by the YARA rule:\n {reset}")
        for bin_info in suid_binaries:
            print(f"{yellow}{bold}Binary:{reset} {bin_info['Binary']}, {yellow}{bold}Path:{reset} {bin_info['Path']}, {yellow}{bold}Owner:{reset} {bin_info['SUID']}, {yellow}{bold}Group:{reset} {bin_info['SGID']}")

        print() 

        if len(sys.argv) != 2:
            print(f"{red}Usage: python script.py <yara_rule.yara>{reset}")
            sys.exit(1)

        rule_path = sys.argv[1]
        check_binaries_with_yara(rule_path, suid_binaries, sudo_password)
    else:
        print(f"{red}No SUID/SGID binaries found.{reset}")


if __name__ == "__main__":
    main()
