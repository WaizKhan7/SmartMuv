from src.ast_parsing.ast_parser import generate_ast
from src.ast_parsing.ast_parser import parse_ast
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

def get_ast_parsing_results(source_code):
    children, _ = generate_ast(source_code)
    children.pop(0)
    all_contracts_details, _ = parse_ast(children)
    return all_contracts_details

def compare_results(current_results, expected_results):
    for cont in expected_results:
        for key in expected_results[cont]:
            if key != 'fbody':
                try:
                    if expected_results[cont][key] != []:
                        for val in expected_results[cont][key]:
                            if val not in current_results[cont][key]:
                                print(cont, key)
                                print("_________________________________")
                                print(expected_results[cont][key])
                                print("_________________________________")
                                print(current_results[cont][key])
                                print("_________________________________")
                                return False
                except Exception as e:
                    print(e)
                    return False
    return True

def ast_parsing_test():
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    test_dir = config.get('test_directories', 'ast_parsing_directory')
    contracts = read_json("contracts", input_dir)
    print("Running AST Parsing Test...")
    passed = 0
    for ind in range(len(contracts)):
        print("Checking on contract #", ind+1)
        contract_name = contracts[ind]['Contract Name']
        source_code = read_source_code(contract_name, input_dir)
        try:
            current_ast_results = get_ast_parsing_results(source_code)
            expected_ast_results = read_json(contract_name, test_dir)
            result = compare_results(current_ast_results, expected_ast_results)
        except:
            result = False
        if result == True:
            passed+=1
    return passed, len(contracts)      

if __name__ == "__main__":
    passed, total = ast_parsing_test()
    if passed < total:
        print(f"Passed {passed} tests out of {total} tests")
    else:
        print("Successfully passed all ast parsing tests!")