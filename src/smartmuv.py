from src.state_extraction.state_extractor import extract_contract_state
import json
import pandas as pd
from configparser import ConfigParser

def read_source_code(contract_name, input_dir):
    input_path = input_dir + contract_name + ".sol"
    f = open(input_path)
    source_code = f.read()
    return source_code


if __name__ == "__main__":
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    with open(input_dir+"/contracts.json") as f:
        contracts = json.load(f)
    for index in range(len(contracts)):
        print(index+1, " ", contracts[index]['Address'], " ", contracts[index]['Contract Name'])
    num = input("Select contract no from above to run SmartMuv -> ")
    contract_name = contracts[int(num)-1]['Contract Name']
    addr = contracts[int(num)-1]['Address']
    source_code = read_source_code(contract_name, input_dir)
    contract_state, current_block_number = extract_contract_state(contract_name, source_code, addr)
    print("\nDetails of Extracted State Variables are:\n")
    for var in contract_state:
        print(var)
        