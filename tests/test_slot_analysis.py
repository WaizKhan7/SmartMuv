from src.state_extraction.state_extractor import get_variables_slot
from configparser import ConfigParser
import json

def read_source_code(contract_name, input_dir):
    input_path = input_dir + contract_name + ".sol"
    f = open(input_path)
    source_code = f.read()
    return source_code

def read_json(file_name, input_dir):
    input_path = input_dir + file_name + ".json"
    with open(input_path) as f:
        read_file = json.load(f)
    return read_file

def compare_results(current_results, expected_results):
    for ind in range(len(expected_results)):
        try:
            if expected_results[ind] != current_results[ind]:
                print("_________________________________")
                print(expected_results[ind])
                print("_________________________________")
                print(current_results[ind])
                print("_________________________________")
                return False
        except:
            print(ind)
            return False
    return True

def run_slot_analysis_test():
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    test_dir = config.get('test_directories', 'slot_analysis_directory')
    contracts = read_json("contracts", input_dir)
    print("Running on Slot Analysis Test...")
    passed = 0
    for ind in range(len(contracts)):
        print("Checking on contract #", ind+1)
        contract_name = contracts[ind]['Contract Name']
        source_code = read_source_code(contract_name, input_dir)
        try:
            current_var_slots = get_variables_slot(contract_name, source_code)
            expected_var_slots = read_json(contract_name, test_dir)
            result = compare_results(current_var_slots, expected_var_slots)
        except:
            result = False
        if result == True:
            passed+=1
    return passed, len(contracts)

if __name__ == "__main__":
    passed, total = run_slot_analysis_test()
    if passed < total:
        print(f"Passed {passed} tests out of {total} tests")
    else:
        print("Successfully passed all slot analysis tests!")