from src.key_approx_analysis.key_approx_analyzer import key_approx_analyzer
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
    expected_results = expected_results['data']
    for cont in expected_results:
        for func in expected_results[cont]:
            try:
                if expected_results[cont][func] != current_results[cont][func]:
                    print(func)
                    print("___________________________________")
                    print(expected_results[func])
                    print("___________________________________")
                    print(current_results[func])
                    print("___________________________________")
                    return False
            except:
                print(func)
                return False
    return True

def key_analysis_test():
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    test_dir = config.get('test_directories', 'key_analysis_directory')
    contracts = read_json("contracts", input_dir)
    print("Running Key Approximation Test...")
    for ind in range(len(contracts)):
        print("Checking on contract #", ind+1)
        contract_name = contracts[ind]['Contract Name']
        source_code = read_source_code(contract_name, input_dir)
        current_analysis_results = key_approx_analyzer(contract_name, source_code)
        expected_analysis_results = read_json(contract_name, test_dir)
        result = compare_results(current_analysis_results, expected_analysis_results)
        if result == False:
            return False
    return True

if __name__ == "__main__":
    res = key_analysis_test()
    if res == False:
        print("Test failed!")
    else:
        print("Successfully completed key approximation test!")