# yara-gtfo

## Usage:

1. Install the packages from requirements.txt
2. Execute the following command:
```python
python3 main/main.py --help                                                                                              
usage: main.py [-h] [-o OUTPUT] general_rules additional_rules

Check binary files using YARA rules.

positional arguments:
  general_rules         Path to the general YARA rule file
  additional_rules      Path to the additional YARA rule file

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Path to the output file for saving results
```
3. Usage example for debian:
```python
python3 main/main.py yara_rulesets/general_rules.yar yara_rulesets/additional_rulesets/debian/debian_additional_rules.yar -o results_for_my_container.txt
```
