import os
import subprocess
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import re

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
            # Извлекаем только теги <p>, <code>, <h2>
            content = []
            for tag in soup.find_all(['p', 'code', 'h2']):
                if tag.name == 'h2':
                    content.append(f"\n{tag.text.strip()}\n")
                elif tag.name == 'p':
                    # Выводим текст тега <p>, включая содержимое <code>, если оно есть
                    content.append(f"{tag.text.strip()}\n")
                elif tag.name == 'code':
                    # Проверяем, что <code> не находится внутри <p>
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
    exploits = []  # Список для хранения потенциальных эксплойтов
    print(Fore.CYAN + Style.BRIGHT + f"\n=== Starting check with {rule_name} ===")
    for binary in binaries:
        try:
            result = subprocess.run(['yara', yara_rule, binary], capture_output=True, text=True)
            if result.stdout.strip():  # Если есть совпадения
                gtfobins_exists, gtfobins_content = check_gtfobins(binary)
                if gtfobins_exists:
                    matched_binaries.add(binary)
                    print(Fore.RED + Style.BRIGHT + f"Check for {binary} failed! Information about how to exploit the privileges for a binary file is available on the GTFOBins resource, visit the resource: https://gtfobins.github.io/gtfobins/{os.path.basename(binary)}/")
                    print(Fore.YELLOW + Style.BRIGHT + f"Possible exploitation for {binary}:")
                    print(gtfobins_content)
                    exploits.append(f"Possible exploitation for {binary}:\n{gtfobins_content}\n")  # Добавляем в список эксплойтов
                else:
                    print(Fore.MAGENTA + Style.BRIGHT + f"There is no information about the exploit for {binary} on the GTFOBins resource! Check your yara rule, it may have returned false positive!")
            else:  # Если совпадений нет
                print(Fore.GREEN + Style.BRIGHT + f"Check for {binary} passed!")
        except Exception as e:
            print(f"Error while checking {binary}: {e}")
        
        # Добавляем разделитель после каждого результата
        print(Fore.CYAN + Style.BRIGHT + "_" * 100)

    print(Fore.CYAN + Style.BRIGHT + f"=== Finished check with {rule_name} ===\n")
    return matched_binaries, exploits  # Возвращаем также список эксплойтов

def clean_output(content):
    # Удаляем цветовые коды и лишние пробелы
    return re.sub(r'\x1B\[[0-?9;]*[mK]', '', content).strip()

if __name__ == "__main__":
    # Настройка парсера аргументов
    parser = argparse.ArgumentParser(description='Check binary files using YARA rules.')
    parser.add_argument('general_rules', help='Path to the general YARA rule file')
    parser.add_argument('additional_rules', help='Path to the additional YARA rule file')
    parser.add_argument('-o', '--output', help='Path to the output file for saving results')
    args = parser.parse_args()

    # Задаем директории для поиска бинарных файлов
    directories_to_search = ['/usr/sbin', '/usr/bin']

    # Находим все бинарные файлы
    binaries = find_binaries(directories_to_search)

    # Начальная надпись
    print(Fore.CYAN + Style.BRIGHT + "Scanning all binary files in the system and checking against the YARA rules...\n")

    # Запускаем проверку с general_rules.yar
    general_matches, general_exploits = run_yara_rule(args.general_rules, binaries, "General Rules")

    # Запускаем проверку с debian_additional_rules.yar
    additional_matches, additional_exploits = run_yara_rule(args.additional_rules, binaries, "Additional Rules")

    # Находим объединение (файлы, которые сработали хотя бы на одно из правил)
    union_matches = general_matches.union(additional_matches)

    # Сохраняем результаты в файл, если указан аргумент -o
    if args.output:
        with open(args.output, 'w') as f:
            f.write("Results for General Rules:\n")
            f.write("\n".join(general_matches) + "\n\n")
            f.write("Results for Additional Rules:\n")
            f.write("\n".join(additional_matches) + "\n\n")
            f.write("Union (General or Additional Rules):\n")
            f.write("\n".join(union_matches) + "\n\n")

            # Добавляем секцию с потенциальными эксплойтами
            f.write("Potential Exploits:\n")
            f.write("\n".join(general_exploits + additional_exploits) + "\n")

    # Финальное сообщение
    print(Fore.CYAN + Style.BRIGHT + "Scanning completed. Results saved to the output file." if args.output else "Scanning completed.")
