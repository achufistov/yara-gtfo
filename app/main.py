import os
import subprocess
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import textwrap
from exploits import shell_bins, sudo_bins, suid_bins, capabilities  # Импортируем словари
from db_handler import create_connection, create_table, insert_binary, get_all_binaries

# Инициализация colorama
init(autoreset=True)

def find_binaries(directories):
    binaries = []
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.access(file_path, os.X_OK):  # Проверяем, является ли файл исполняемым
                    binaries.append(file_path)
    return binaries

def check_gtfobins(binary):
    binary_name = os.path.basename(binary)
    url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            content = []
            for tag in soup.find_all(['p', 'code', 'h2']):
                if tag.name == 'h2':
                    content.append(f"\n{tag.text.strip()}\n")
                elif tag.name == 'p':
                    content.append(f"{tag.text.strip()}\n")
                elif tag.name == 'code':
                    if not tag.find_parent('p'):
                        content.append(f"{tag.text.strip()}\n")
            return True, "\n".join(content)
        elif response.status_code == 404:
            return False, None
    except Exception as e:
        print(f"Error while checking GTFOBins for {binary_name}: {e}")
    return False, None

def run_yara_rule(yara_rule, binaries, rule_name):
    matched_binaries = set()
    exploits = []
    print(Fore.CYAN + Style.BRIGHT + f"\n=== Starting check with {rule_name} ===")
    for binary in binaries:
        try:
            result = subprocess.run(['yara', yara_rule, binary], capture_output=True, text=True)
            if result.stdout.strip():
                gtfobins_exists, gtfobins_content = check_gtfobins(binary)
                if gtfobins_exists:
                    matched_binaries.add(binary)
                    print(Fore.RED + Style.BRIGHT + f"Check for {binary} failed! Information about how to exploit the privileges for a binary file is available on the GTFOBins resource, visit the resource: https://gtfobins.github.io/gtfobins/{os.path.basename(binary)}/")
                    print(Fore.YELLOW + Style.BRIGHT + f"Possible exploitation for {binary}:")
                    print(gtfobins_content)
                    exploits.append(f"Possible exploitation for {binary}:\n{gtfobins_content}\n")
                else:
                    print(Fore.MAGENTA + Style.BRIGHT + f"There is no information about the exploit for {binary} on the GTFOBins resource! Check your yara rule, it may have returned false positive!")
            else:
                print(Fore.GREEN + Style.BRIGHT + f"Check for {binary} passed!")
        except Exception as e:
            print(f"Error while checking {binary}: {e}")
        
        print(Fore.CYAN + Style.BRIGHT + "_" * 100)

    print(Fore.CYAN + Style.BRIGHT + f"=== Finished check with {rule_name} ===\n")
    return matched_binaries, exploits

def format_exploit_info(exploit_info):
    formatted_sections = []
    current_section = []
    lines = exploit_info.split("\n")

    for line in lines:
        if any(header in line for header in ["Shell", "SUID", "Sudo"]):
            if current_section:
                formatted_sections.append("\n".join(current_section))
                current_section = []
            current_section.append(Fore.YELLOW + Style.BRIGHT + f"  {line.strip()}" + Style.RESET_ALL)
        else:
            current_section.append("    " + line.strip())

    if current_section:
        formatted_sections.append("\n".join(current_section))

    return "\n\n".join(formatted_sections)

def format_binary_info(binary_path, exploit_info):
    binary_header = Fore.CYAN + Style.BRIGHT + "Binary:" + Style.RESET_ALL
    binary_formatted = textwrap.fill(binary_path, width=80, initial_indent="  ", subsequent_indent="  ")
    exploit_header = Fore.CYAN + Style.BRIGHT + "Exploit Info:" + Style.RESET_ALL
    exploit_formatted = format_exploit_info(exploit_info)

    formatted_output = (
        f"{binary_header}\n{binary_formatted}\n\n"
        f"{exploit_header}\n{exploit_formatted}\n"
        f"{Fore.CYAN}{'-' * 80}{Style.RESET_ALL}"
    )
    return formatted_output

def parse_exploit_info(exploit_info):
    categories = {}
    current_category = None
    lines = exploit_info.split("\n")

    for line in lines:
        line = line.strip()
        if line in ["Shell", "SUID", "Sudo"]:
            current_category = line
            categories[current_category] = []
        elif line and current_category:
            categories[current_category].append(line)

    return categories

def execute_exploit(command):
    try:
        print(Fore.YELLOW + f"Executing: {command}" + Style.RESET_ALL)
        # Используем Popen для запуска команды и передачи управления
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Передаем управление процессу
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(Fore.GREEN + "Command executed successfully!" + Style.RESET_ALL)
            print(Fore.CYAN + "Output:" + Style.RESET_ALL)
            print(stdout.decode())
            return True  # Возвращаем True, если команда выполнена успешно
        else:
            print(Fore.RED + f"Error executing command: {stderr.decode()}" + Style.RESET_ALL)
            return False  # Возвращаем False, если произошла ошибка
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)
        return False

def user_interaction(conn):
    while True:  # Цикл для возврата к выбору команд
        binaries = get_all_binaries(conn)
        for binary in binaries:
            binary_path = binary[1]
            exploit_info = binary[2]
            print(format_binary_info(binary_path, exploit_info))

            # Разбираем информацию об эксплойте
            categories = parse_exploit_info(exploit_info)

            # Создаем общий пул команд
            available_commands = []
            for category in categories.keys():
                if category == "SUID":
                    commands = suid_bins.get(os.path.basename(binary_path), [])
                elif category == "Sudo":
                    commands = sudo_bins.get(os.path.basename(binary_path), [])
                elif category == "Shell":
                    commands = shell_bins.get(os.path.basename(binary_path), [])
                elif category == "Capabilities":
                    commands = capabilities.get(os.path.basename(binary_path), [])
                else:
                    commands = []

                for command in commands:
                    available_commands.append((command, category))  # Сохраняем команду и ее категорию

            # Предлагаем пользователю выбрать команду
            while True:  # Цикл для выбора команды
                print(Fore.CYAN + "Available commands:" + Style.RESET_ALL)
                for i, (command, category) in enumerate(available_commands, start=1):
                    print(f"{i}. [{category}] {command}")

                command_choice = input("Enter the number of the command you want to execute (or 'skip' to skip): ")
                if command_choice.lower() == 'skip':
                    print("Skipping...")
                    break  # Выход из цикла выбора команды

                try:
                    command_choice = int(command_choice)
                    if command_choice < 1 or command_choice > len(available_commands):
                        print(Fore.RED + "Invalid choice, skipping..." + Style.RESET_ALL)
                        break  # Выход из цикла выбора команды

                    selected_command = available_commands[command_choice - 1][0]  # Получаем только команду

                    # Запрашиваем подтверждение выполнения
                    confirm = input(Fore.YELLOW + "Are you sure you want to execute this command? (yes/no): " + Style.RESET_ALL)
                    if confirm.lower() == 'yes':
                        if execute_exploit(selected_command):
                            # Если команда выполнена успешно, запускаем новую оболочку
                            print(Fore.GREEN + "You now have elevated privileges. Type 'exit' to return to the program." + Style.RESET_ALL)
                            subprocess.call(['/bin/sh'])  # Запускаем новую оболочку
                        else:
                            print("Command execution failed.")
                    else:
                        print("Command execution cancelled. Returning to command selection.")
                except ValueError:
                    print(Fore.RED + "Invalid input, please try again." + Style.RESET_ALL)

        print("Thank you for using yara-gtfo")
        break  # Выход из цикла после завершения работы

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check binary files using YARA rules.')
    parser.add_argument('general_rules', help='Path to the general YARA rule file')
    parser.add_argument('additional_rules', help='Path to the additional YARA rule file')
    parser.add_argument('-o', '--output', help='Path to the output file for saving results')
    args = parser.parse_args()

    directories_to_search = ['/usr/sbin', '/usr/bin']
    binaries = find_binaries(directories_to_search)

    print(Fore.CYAN + Style.BRIGHT + "Scanning all binary files in the system and checking against the YARA rules...\n")

    general_matches, general_exploits = run_yara_rule(args.general_rules, binaries, "General Rules")
    additional_matches, additional_exploits = run_yara_rule(args.additional_rules, binaries, "Additional Rules")

    union_matches = general_matches.union(additional_matches)

    if args.output:
        with open(args.output, 'w') as f:
            f.write("Results for General Rules:\n")
            f.write("\n".join(general_matches) + "\n\n")
            f.write("Results for Additional Rules:\n")
            f.write("\n".join(additional_matches) + "\n\n")
            f.write("Union (General or Additional Rules):\n")
            f.write("\n".join(union_matches) + "\n\n")
            f.write("Potential Exploits:\n")
            f.write("\n".join(general_exploits + additional_exploits) + "\n")

    conn = create_connection("binaries.db")
    if conn is not None:
        create_table(conn)
        for binary in union_matches:
            gtfobins_exists, gtfobins_content = check_gtfobins(binary)
            if gtfobins_exists:
                insert_binary(conn, (binary, gtfobins_content))
        user_interaction(conn)
        conn.close()
    else:
        print("Error! cannot create the database connection.")

    print(Fore.CYAN + Style.BRIGHT + "Scanning completed. Results saved to the output file." if args.output else "Scanning completed.")