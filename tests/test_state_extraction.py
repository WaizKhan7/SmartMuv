from src.state_extraction.state_extractor import extract_contract_state
from configparser import ConfigParser
import json
import ast

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

def compare_results(current_results, expected_contract_state):
    expected_results = ast.literal_eval(expected_contract_state['data'])
    current_results_names = [var[0] for var in current_results]
    current_results_type = [var[1] for var in current_results]
    for exp_var in expected_results:
        if not exp_var[0] in current_results_names and exp_var[1] in current_results_type:
            print(exp_var[0])
            return False
    return True

def run_state_extraction_test():
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    test_dir = config.get('test_directories', 'extraction_directory')
    contracts = read_json("contracts", input_dir)
    print("Running State Extraction Test...")
    for ind in range(len(contracts)):
        print("Checking on contract #", ind+1)
        contract_name = contracts[ind]['Contract Name']
        addr = contracts[ind]['Address']
        source_code = read_source_code(contract_name, input_dir)
        current_contract_state, _ = extract_contract_state(contract_name, source_code, addr)
        expected_contract_state = read_json(contract_name, test_dir)
        result = compare_results(current_contract_state, expected_contract_state)
        if result == False:
            return False
    return True

if __name__ == "__main__":
    res = run_state_extraction_test()
    if res == False:
        print("Result failed!")
    else:
        print("Successfully completed state extraction test!")