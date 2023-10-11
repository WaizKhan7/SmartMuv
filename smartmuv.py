from src.state_extraction.state_extractor import extract_contract_state, extract_regular_variables
from src.key_approx_analysis.key_approx_analyzer import get_slot_details
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
    
    contract_name = "CommunityBankCoin"
    cont_addr = "0x143e685dd51d467d77663a3be119217185d81b99"
    compiler_version = "0.4.25"
    # you can either add network of your own choice or choose from the following options:
    # "test" (Goerli), "mainnet" (Ethereum Mainnet), "mumbai", "polygon", "bsctest", and "bsc"
    network = "mainnet"    
    source_code = read_source_code(contract_name, input_dir)
    print("Select the SmartMuv feature you want to use (1-3):")
    options = """
    1 - Get Variable Slot Layout Details.
    2 - Extract Regular Variables.
    3 - Extract Complete State.
    
    Your Option - """
    option = input(options)
    print("\n")
    if option == "1":
        slots_details = get_slot_details(contract_name, source_code, compiler_version)
        print("\nContract Slot Layout is as follows:\n")
        for slot in slots_details:
            print(slot)

    elif option == "2":
        results, slots_details, slots_and_data, block_number = extract_regular_variables(
            contract_name, source_code, cont_addr, compiler_version, "mainnet")
        print("\nDetails of Extracted Regular Variables are:\n")
        for var in results:
            print(var)

    elif option == "3":
        contract_state, variables_slot_results, slots_and_data, key_analysis_result, block_number = extract_contract_state(
            contract_name, source_code, cont_addr, compiler_version, "mainnet")
        print("\nDetails of Extracted Contract State:\n")
        for var in contract_state:
            print(var)
    