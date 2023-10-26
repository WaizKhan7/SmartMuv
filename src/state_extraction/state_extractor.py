from logging import raiseExceptions
import pprint
from src.key_approx_analysis.key_approx_analyzer import extract_slot_details, generate_final_key_approx_results, get_contract_details, get_contract_details_new, key_approx_analyzer
from src.state_extraction.transactions import get_internal_transactions
from src.state_extraction.transactions import get_transactions
from src.state_extraction.slot_calculator import calculate_slots
from src.ast_parsing.ast_parser import generate_ast
import collections
import itertools
import math
from hexbytes import HexBytes
import warnings
import solcx
from solcx import compile_source
from solc_select import solc_select
from web3.auto import Web3
from web3.middleware import geth_poa_middleware
from configparser import ConfigParser
import copy
warnings.filterwarnings("ignore")

# switch Solidity compiler to required version
def switch_compiler(compiler_version):
    if compiler_version != '':
        for i in range(len(compiler_version)):
            if compiler_version[i].isdigit():
                compiler_version = compiler_version[i:]
                break
        for i in range(len(compiler_version)):
            if not compiler_version[len(compiler_version)-i-1].isdigit():
                compiler_version = compiler_version[:len(compiler_version)-i-1]
                break
            else:
                break
        if len(compiler_version.split('<=')) > 1:
            compiler_version = compiler_version.split('<=')[1]
        if len(compiler_version.split('<')) > 1:
            compiler_version = compiler_version.split('<')[1]
        compiler_version = compiler_version.split('>')[0]
        compiler_version = compiler_version.split('^')[0]
        if compiler_version.count('.') == 1:
            compiler_version += '.0'
        if '0.3' in compiler_version:
            compiler_version = '0.4.24'
        if '0.4.1' in compiler_version and len(compiler_version) <= 5:
            compiler_version = '0.4.24'

        if str(solcx.get_solc_version()) != compiler_version:
            try:
                solcx.set_solc_version(compiler_version)
                print('solcx ->', solcx.get_solc_version())
            except Exception as e:
                try:
                    solcx.install_solc(compiler_version)
                    solcx.set_solc_version(compiler_version)
                except:
                    pass
        if solc_select.current_version()[0] != compiler_version:
            try:
                solc_select.switch_global_version(compiler_version, True)
                print('solc ->', solc_select.current_version()[0])
            except Exception as e:
                print(str(e))

    return


def get_final_results(results):
    final_results = []
    for res in results:
        if not (res[-3]  == "0x0000000000000000000000000000000000000000" and "key" in res[0]):
            final_results.append(res)
    return final_results

# transforms raw extracted data into readable format
def generate_readable_results(contract_addr, results, w3):
    for var in results:
        if len(var) < 5:
            continue 
        if ('int' in var[1] and len(var) > 3) or 'uint' in var[1]:
            try:
                var[2] = w3.to_int(var[2])
            except:
                try:
                    var[2] = w3.to_int(hexstr=var[2])
                except:
                    continue
        elif 'bool' in var[1]:
            try:
                var[2] = w3.to_int(var[2])
            except:
                try:
                    var[2] = w3.to_int(hexstr=var[2])
                except:
                    continue
            if var[2] == 1:
                var[2] = "True"
            if var[2] == 0:
                var[2] = "False"
        elif 'string' in var[1]:
            try:
                var[2] = var[2].decode("utf-8").split(u'\x00')[0]
            except Exception as e:
                # if string size is greater than 32 bytes and not in length slots
                try:
                    string_length = int(w3.to_hex(var[2][31:]), 16) # getting length saved at 32nd byte
                    string_data_slot = w3.solidity_keccak(['uint256'], [int(var[4], 16)]) # calculating string data slot
                    string_data_slot = w3.to_int(string_data_slot)
                    complete_string = ''
                    for curr_slot in range(0, math.ceil(string_length/64)):
                        val = w3.eth.get_storage_at(w3.to_checksum_address(contract_addr), string_data_slot+curr_slot)
                        complete_string += val.decode("utf-8").split(u'\x00')[0]
                    var[2] = complete_string #updating string value
                    var[4] += "|"+str(string_data_slot) # updating string slot with string data slot
                    var[3] = string_length # updating string length
                except Exception as e:
                    print(e)
                    pass
        else:
            try:
                var[2] = w3.to_hex(var[2])
            except:
                var[2] = w3.to_hex(w3.to_bytes(hexstr=var[2]))
    return results

#convert raw value to provided variable type
def get_variable_value(var_value, var_type , w3):
    if 'int' in var_type or 'uint' in var_type:
        try:
            var_value = w3.to_int(var_value)
        except:
            var_value = int(var_value)
    elif 'string' in var_type:
        try:
            var_value = var_value.decode("utf-8").split(u'\x00')[0]
        except:
            pass
    else:
        try:
            var_value = w3.to_hex(var_value)
            var_value = str(bytearray.fromhex(var_value[2:]).decode())
            var_value = var_value.rstrip('\x00')
        except:
            var_value = w3.to_hex(w3.to_bytes(hexstr=var_value))
    return var_value

def hex_to_declared_type(var_value, var_type , w3):
    if 'int' in var_type or 'uint' in var_type:
        try:
            #var_value = w3.to_int(var_value)
            var_value = int(var_value, 0)
        except:
            raiseExceptions
    if 'bytes' in var_type:
        try:
            var_value = w3.to_hex(var_value)
            var_value = str(bytearray.fromhex(var_value[2:]).decode())
            var_value = var_value.rstrip('\x00')
        except:
            var_value = w3.to_hex(w3.to_bytes(hexstr=var_value))
    return var_value


def transform_result(results):

    var_data = []
    mapping_data = []
    for res in results:
        if res[2] != 0:
            if 'key' in res[0]:
                details = res[0].split(":")
                name = details[0]
                key = details[2]
                mapping_data.append([name, key, res[1], res[2], res[3]])
            else:
                var_data.append(res)
                
    return mapping_data


def generate_abi(source_code, cont_name):
    compiled_contracts = compile_source(source_code)
    for contract in compiled_contracts:
        curr_cont_name = contract.split(":")[1]
        if cont_name == curr_cont_name:
            cont_abi = compiled_contracts[contract]['abi']
            break
    return cont_abi

# extracts data/values of regular/elementary variables
def extract_elementry_variables(ord_slots, cont_addr, slots_and_data, w3):

    var_lst = []
    for ind, key in enumerate(ord_slots.keys()):
        if not ind % 100:
            print(f"Extracted {ind} out of {len(ord_slots)}")
        vars1 = ord_slots[key]
        val = w3.eth.get_storage_at(w3.to_checksum_address(cont_addr), key)
        bytes_used = 0
        byte_str = val
        sep_bytes = [byte_str[i:i+1] for i in range(0, len(byte_str), 1)]
        if len(sep_bytes) == 1:
            sep_bytes[0] = HexBytes(HexBytes('0x00')+HexBytes(sep_bytes[0]))
        # as one slot is 32 bytes, list must have 32 entries
        sep_bytes = [HexBytes('0x00')] * (32 - len(sep_bytes))+sep_bytes
        var_names = [var['name'] for var in vars1]
        hex_val = w3.to_hex(b''.join(sep_bytes))
        if hex_val != "0x0000000000000000000000000000000000000000000000000000000000000000":
            if [str(val), hex_val, hex(key), var_names] not in slots_and_data:
                slots_and_data.append([str(val), hex_val, hex(key), var_names])
        if len(vars1) > 1:
            sep_bytes.reverse()
            for var in vars1:
                tmp = []
                for j in range(math.ceil(bytes_used), math.ceil((bytes_used+var['bytes']))):
                    try:
                        tmp.append(sep_bytes[j])
                    except Exception as e:
                        print(e)
                bytes_used += var['bytes']
                tmp.reverse()
                # print(b''.join(tmp))
                extracted_var = [var['name'], var['dataType'], b''.join(tmp), var['bytes'], hex(key)]
                var_lst.append(extracted_var) 
        else:
            sep_bytes.reverse()
            tmp = []
            for j in range(0, math.ceil(vars1[0]['bytes'])):
                try:
                    tmp.append(sep_bytes[j])
                except Exception as e:
                    print(e)
            tmp.reverse()
            extracted_var = [vars1[0]['name'], vars1[0]['dataType'], b''.join(tmp), vars1[0]['bytes'], hex(key)]
            var_lst.append(extracted_var)
    print("Completed!")
    return var_lst, slots_and_data

# extracts data/values of user-defined variables
def extract_user_defined_vars_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3):
    try:
        all_vars = extract_variables_data_from_chain(
            cont_addr, var['object']['typeVars'], all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
    except:
        all_vars = extract_variables_data_from_chain(
            cont_addr, var['typeVars'], all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
    return all_vars

# extracts data/values of array type variables
def extract_array_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3):
                
    levels = len(var['length'])  # levels/dimensions of array
    if levels == 1:
        tmpc = [['', var['slot']]]
    if levels > 1:
        for i in range(0, levels-1):
            if i == 0:
                tmpc = [['', var['slot']]]
            tmp_lst = []
            for q in range(0, len(tmpc)):
                slot = tmpc[q][1]
                # "array_length" is no of entries (N-1 Dimension) in the array
                array_length = w3.to_int(w3.eth.get_storage_at(
                    w3.to_checksum_address(cont_addr), slot))
                start_slot = w3.to_int(w3.solidity_keccak(['uint256'], [slot]))
                for idx in range(0, array_length):
                    loc = start_slot + idx
                    tmp_lst.append([tmpc[q][0]+str(idx)+':', loc])
            tmpc = tmp_lst[:]

    count = 0
    for key_details in tmpc:
        g = w3.to_int(w3.eth.get_storage_at(
            w3.to_checksum_address(cont_addr), key_details[1]))
        f = w3.to_int(w3.solidity_keccak(['uint256'], [key_details[1]]))
        var_dict = {}
        var_dict['type'] = 'ArrayTypeName'
        var_dict['dataTypeType'] = var['dataTypeType']
        var_dict['dataTypeName'] = var['dataTypeName']
        var_dict['length'] = str(g)
        var_dict['name'] = var['name']+':'+str(count)
        count = count+1
        var_dict['curr'] = -1
        var_dict['dimension'] = 'single'
        var_dict['StorageType'] = 'static'

        _, slot_results = calculate_slots([var_dict], f-1, all_contracts)
        all_vars = extract_variables_data_from_chain(cont_addr, slot_results, all_contracts, contract_abi,
                            all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
    return all_vars

# extracts data/values of mapping type variables
def extract_mapping_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3):
    keys_type = []
    mapping_ast = var
    all_possible_keys = []
    key_dim = 1
    val = var['valueType']
    while 'valueType' in mapping_ast:
        keys_type.append(mapping_ast['keyType'])
        mapping_ast = mapping_ast['valueType']
    while 'keyType' in val:
        key_dim += 1
        val = val['valueType']            

    if len(key_approx_results) != 0:
        for func_name in key_approx_results.keys():
            keys_details_lst = key_approx_results[func_name]
            print("extracting key values of mappings ->", var['name'], "for function ->", func_name, "->", len(keys_details_lst))
            all_keys = []
            for key_details in keys_details_lst:
                if key_details[0] == var['name']:
                    all_dim_keys = [key_details[q:q + 6] for q in range(0, len(key_details), 6)]
                    if len(all_dim_keys) != key_dim:
                        continue
                    for i, key in enumerate(all_dim_keys):
                        not_global  = True
                        if key[3] == 'Global':
                            g_found = False
                            not_global = False
                            for g_var in all_vars:
                                if key[1] == g_var[0]:
                                    g_var_value = get_variable_value(g_var[2], g_var[1], w3)
                                    print(f"Global variables key ({g_var[0]})->", g_var_value)
                                    key_details[2+(i*6)] = g_var_value
                                    g_found = True
                    if not_global:   
                        all_keys.append(key_details)
                    else:
                        if g_found:
                            all_keys.append(key_details)
            for key in all_keys:
                # extracting key details of each key in case mapping is multi dimensional
                dim_keys = [key[q:q + 6] for q in range(0, len(key), 6)]
                dim = {}
                for lev, curr_key in enumerate(dim_keys):
                    if curr_key[3] == 'Static' or curr_key[3] == 'NEW' or curr_key[3] == 'Global':
                        # extracting keys details 0th index contains function name, and 1st index contains key details
                        # curr_key[2] contains key value
                        if lev in dim:
                            dim[lev].append([curr_key[2], keys_type[lev]['name']])
                        else:
                            dim[lev] = [[curr_key[2], keys_type[lev]['name']]]
                    else:
                        if func_name in tx_arg_details:
                            trans_func_args = tx_arg_details[func_name]
                            for trans in trans_func_args:
                                # transaction_abi contains name and type of function argument
                                func_arg_details = trans[0]
                                transaction_abi = func_arg_details[0].abi['inputs']
                                transaction_abi.append({'name': 'msg.sender', 'type': 'address'})
                                # inputs contains values of function argument passed as input
                                func_inputs = func_arg_details[1]
                                # index 1 contains from address of transaction
                                func_inputs['msg.sender'] = trans[1]
                                # curr_key[4] contains position of the key argument within function arguments
                                key_arg_pos = int(curr_key[4])
                                for arg in func_inputs.keys():
                                    # finding arg name at required "key_arg_pos" to extract its value
                                    if arg == transaction_abi[int(key_arg_pos)]['name']:
                                        if lev in dim:
                                            dim[lev].append(
                                            [func_inputs[arg], transaction_abi[key_arg_pos]['type']])
                                        else:
                                            dim[lev] = [[func_inputs[arg], transaction_abi[key_arg_pos]['type']]]
                                        break
                # if keys for all dimensions are extracted successfully
                if len(dim) == len(dim_keys):
                    diff_lens = False
                    keys_list = []
                    dict_keys = list(dim.keys())
                    first_len = len(dim[dict_keys[0]])
                    for key_idx in dim:
                        keys_list.append(dim[key_idx])
                        if first_len != len(dim[key_idx]):
                            diff_lens = True
                    # if length of all the keys for every dimension is not same
                    if diff_lens == True:
                        all_combinations = list(itertools.product(*keys_list))
                        for comb in all_combinations:
                            if list(comb) not in all_possible_keys:
                                all_possible_keys.append(list(comb))
                    else:
                        for ind in range(len(dim[dict_keys[0]])):
                            keyy = []
                            for key_idx in dict_keys:
                                keyy += [dim[key_idx][ind]]
                                if keyy not in all_possible_keys:
                                    all_possible_keys.append(keyy)
                            
    map_slots = []
    for all_dim_keys in all_possible_keys:
        #sub contains key and key type respectively
        placeholder = []
        for lev in range(0, key_dim):
            key_type = all_dim_keys[lev][1]
            key_val = all_dim_keys[lev][0]
            if key_type == 'address':
                try:
                    slot_key = [w3.to_int(hexstr=key_val), key_val]
                    placeholder.append(slot_key)
                except Exception as e:
                    print(key_type, key_val, e)
            elif 'string' in key_type:
                try:
                    slot_key = [key_val, key_val]
                    placeholder.append(slot_key)
                except Exception as e:
                    print(key_type, key_val, e)
            elif 'bytes' in key_type:
                try:
                    key_val = w3.to_hex(key_val)
                    slot_key = [w3.to_int(hexstr=key_val), key_val]
                    placeholder.append(slot_key)
                except:
                    try:
                        slot_key = [w3.to_int(hexstr=key_val), key_val]
                        placeholder.append(slot_key)
                    except Exception as e:
                        print(key_type, key_val, e)
            elif 'uint' in key_type:
                slot_key = [int(key_val), key_val]
                placeholder.append(slot_key)
            else:
                print("skipped...", key_type, key_val)

        slot = var['slot']
        keyss = []
        #placeholder contains [int(key_val) and key_val], and the no of keys depends upon the dimensions of the mapping
        for key_vals in placeholder:
            #slot contain slot no of mapping, then slot against key (vr[0]) is calculated 
            # in case of 2d mapping process will twice
            if key_type == "string":
                try:
                    f = w3.solidity_keccak(['string', 'uint256'], [key_val, slot])
                except Exception as e:
                    print(e)
                    continue
            else:
                try:
                    f = w3.solidity_keccak(['uint256', 'uint256'], [key_vals[0], slot])
                except Exception as e:
                    print(e)
                    continue
            slot = w3.to_int(f)
            keyss.append(key_vals[1])
        if [slot] + keyss not in map_slots:
            map_slots.append([slot]+keyss)

    val = var['valueType']
    while 'valueType' in val:
        val = val['valueType']

    print("Total slots approximated ->", len(map_slots))
    i=0
    for slot in map_slots:
        if not i%200:
            print("extracting no ->", i)
        i+=1
        if slot[0] not in all_slots:
            all_slots.append(slot[0])
            var_dict = {}
            try:
                var_dict['type'] = val['type']
            except:
                var_dict['type'] = val['nodeType']
            if var_dict['type'] == 'ElementaryTypeName':
                var_dict['dataType'] = val['name']
            elif var_dict['type'] == 'UserDefinedTypeName':
                try:
                    var_dict['dataType'] = val['namePath']
                    var_dict['typeVars'] = all_contracts[var_dict['dataType']]['vars']
                except Exception as e:
                    try:
                        if 'pathNode' in val:
                            var_dict['dataType'] = val['pathNode']['name']
                        else:
                            var_dict['dataType'] = val['name']
                        if '.' in var_dict['dataType']:
                            var_dict['dataType'] = var_dict['dataType'].split('.')[-1]
                        var_dict['typeVars'] = all_contracts[var_dict['dataType']]['vars']
                    except Exception as e:
                        print("Warning: Could not extract -", var['name'], e)
                        continue
                    
            keyss = ''
            for key in slot[1:]:
                keyss = keyss+":"+str(key)
            var_dict['name'] = var['name'] + ":key" + keyss
            try:
                _, slot_results = calculate_slots([var_dict], slot[0] - 1, all_contracts)
                all_vars = extract_variables_data_from_chain(cont_addr, slot_results, all_contracts, contract_abi,
                                    all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
            except Exception as e:
                print("Warning: Could not extract -", var_dict['name'], e)
                
    return all_vars

def extract_variables_data_from_chain(cont_addr, vars_slot, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3):
    """
    Take state variables and return their extracted value from the chain.

    Parameters:
        cont_addr (str): Address of the contract.
        vars_slot (list): Holds list of all state variables and slot details.
        all_contracts (list): Holds details of all contracts.
        contract_abi (list): ABI of the contract.
        all_vars (str): Holds values of extracted variable.
        key_approx_results (list): Holds results of key approximation analysis.
        tx_arg_details (dict): List of all arguments extracted from transactions of every function.
        slots_and_data (list): list of slot and data already extracted.
        all_slots (list): list of slots already extracted/checked (used to make sure same value is not extracted multipe times).
        w3 (object): web3 object.

    Returns:
        all_vars (list): list of all extracted values of provided variables.
    """
    elementary_vars = {}
    for var in vars_slot:
        if var['type'] == 'ElementaryTypeName':
            if var['slot'] not in elementary_vars:
                elementary_vars[var['slot']] = [var]
            else:
                elementary_vars[var['slot']].append(var)
                
    ord_slots = collections.OrderedDict(sorted(elementary_vars.items()))
    var_lst, slots_and_data = extract_elementry_variables(ord_slots, cont_addr, slots_and_data, w3)
    all_vars = all_vars + [var for var in var_lst]

    for var in vars_slot:
        if var['type'] == 'UserDefinedTypeName':
            all_vars = extract_user_defined_vars_data(
                cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
        if var['type'] == 'ArrayTypeName':
            all_vars = extract_array_data(
                cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
        if var['type'] == 'Mapping':
            all_vars = extract_mapping_data(
                cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, tx_arg_details, slots_and_data, all_slots, w3)
            print("mapping key-values extracted!")
    return all_vars


def get_variables_slot(cont_name, source_code):
    """
    Takes in contract name, and source code, returns list of variable with their slot details.
    
    Parameters:
        cont_name (str): contract name.
        source_code (str): source code of the contract.
    
    Returns:
        variables_slot_results (dict): details of slots of all state variables.
    """
    children, _ = generate_ast(source_code)
    children.pop(0)
    _, all_contracts_dict = get_contract_details(children)
    _, variables_slot_results = calculate_slots(
        all_contracts_dict[cont_name]['vars'], -1, all_contracts_dict)
    return variables_slot_results


def extract_regular_variables(cont_name, source_code, cont_addr, compiler_version, net):
    """
    Takes contracts source code and other details and extracts values of all regular variables. 

    Parameters:
        cont_name (str): contract name.
        source_code (str): source code of the contract.
        cont_addr (str): contract address.
        compiler_version (str): required Solidity compiler version.
        net (str): Blockchain Network (should be configured in config.ini file).

    Returns:
        results (list): list of regular variables with extracted values.
        slot_details (list): slot/storage layout.
        slots_and_data (list): slots and their data/value.
        block['number] (int): current block number.
    """    
    config = ConfigParser()
    config.read("config.ini")
    if net == "test":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'infura_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'infura_test_pid')
    elif net == "mainnet":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'infura_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'infura_pid')
    elif net == "mumbai":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_poly_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_poly_test_pid')
    elif net == "polygon":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_poly_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_poly_pid')
    elif net == "bsctest":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_bsc_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_bsc_test_pid')
    elif net == "bsc":
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_bsc_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_bsc_pid')

    w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_NODE_LINK + BLOCKCHAIN_NODE_PID))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    if compiler_version != '':
        children, _ = generate_ast(source_code)
        switch_compiler(compiler_version)
    else:
        children, compiler_version = generate_ast(source_code)
        switch_compiler(compiler_version)
    children.pop(0)
    try:
        compiled_sol = compile_source(source_code)
        cont_ast = compiled_sol['<stdin>:'+cont_name]['ast']['nodes']
        all_vars, all_contracts_dict = get_contract_details_new(cont_ast)
    except Exception as e:
        print("Warning - in get_contract_details_new ---", e)
        all_vars, all_contracts_dict = get_contract_details(children)

    _, variables_slot_results = calculate_slots(
        all_contracts_dict[cont_name]['vars'], -1, all_contracts_dict)
    slot_details = extract_slot_details(variables_slot_results)
    slots_and_data = []
    print("Extracting data from chain...")
    elementary_vars = {}
    for var in variables_slot_results:
        if var['type'] == 'ElementaryTypeName':
            if var['slot'] not in elementary_vars:
                elementary_vars[var['slot']] = [var]
            else:
                elementary_vars[var['slot']].append(var)                
    ord_slots = collections.OrderedDict(sorted(elementary_vars.items()))
    var_lst, _ = extract_elementry_variables(ord_slots, cont_addr, slots_and_data, w3)
    all_vars = all_vars + [var for var in var_lst]
    results = all_vars
    results = generate_readable_results(cont_addr, results, w3)
    block = w3.eth.get_block('latest')
    return results, slot_details, slots_and_data, block['number']


def extract_contract_state(cont_name, source_code, cont_addr, compiler_version, net):
    """
    Takes contracts source code and other details and extracts complete state of the smart contract. 

    Parameters:
        cont_name (str): contract name.
        source_code (str): source code of the contract.
        cont_addr (str): contract address.
        compiler_version (str): required Solidity compiler version.
        net (str): Blockchain Network (should be configured in config.ini file).

    Returns:
        final_results (list): list of all state variables with extracted values.
        slot_details (list): slot/storage layout.
        slots_and_data (list): slots and their data/value.
        key_analysis_result (dict): contains details of mapping keys' sources (all contracts).
        block['number] (int): current block number.
    """    
    
    config = ConfigParser()
    config.read("config.ini")
    if net == "test":
        BLOCK_SCANNER_API_KEY = config.get('etherscan', 'etherscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'infura_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'infura_test_pid')
        TRANSACTION_LINK = config.get('etherscan', 'test_transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('etherscan', 'test_internal_transaction_link')
    elif net == "mainnet":
        BLOCK_SCANNER_API_KEY = config.get('etherscan', 'etherscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'infura_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'infura_pid')
        TRANSACTION_LINK = config.get('etherscan', 'transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('etherscan', 'internal_transaction_link')
    elif net == "mumbai":
        BLOCK_SCANNER_API_KEY = config.get('polygonscan', 'polygonscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_poly_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_poly_test_pid')
        TRANSACTION_LINK = config.get('polygonscan', 'test_transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('polygonscan', 'test_internal_transaction_link')
    elif net == "polygon":
        BLOCK_SCANNER_API_KEY = config.get('polygonscan', 'polygonscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_poly_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_poly_pid')
        TRANSACTION_LINK = config.get('polygonscan', 'transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('polygonscan', 'internal_transaction_link')
    elif net == "bsctest":
        BLOCK_SCANNER_API_KEY = config.get('bscscan', 'bscscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_bsc_test_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_bsc_test_pid')
        TRANSACTION_LINK = config.get('bscscan', 'test_transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('bscscan', 'test_internal_transaction_link')
    elif net == "bsc":
        BLOCK_SCANNER_API_KEY = config.get('bscscan', 'bscscan_api_key')
        BLOCKCHAIN_NODE_LINK = config.get('infura', 'rpc_bsc_node_link')
        BLOCKCHAIN_NODE_PID = config.get('infura', 'rpc_bsc_pid')
        TRANSACTION_LINK = config.get('bscscan', 'transaction_link')
        INTERNAL_TRANSACTION_LINK = config.get('bscscan', 'internal_transaction_link')


    w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_NODE_LINK + BLOCKCHAIN_NODE_PID))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    all_transactions = []
    if compiler_version != '':
        switch_compiler(compiler_version)
    else:
        _, compiler_version = generate_ast(source_code)
        switch_compiler(compiler_version)

    key_analysis_result, complete_analysis_results = key_approx_analyzer(cont_name, source_code, compiler_version)
    all_vars = complete_analysis_results['all_vars']
    variables_slot_results = complete_analysis_results['variables_slot_results']
    all_contracts_dict = complete_analysis_results['all_contracts_dict']
    slot_details = complete_analysis_results['slot_details']
    
    contract_abi = generate_abi(source_code, cont_name)

    print("Retrieving transactions:")
    all_transactions = get_transactions(cont_addr, all_transactions, TRANSACTION_LINK, BLOCK_SCANNER_API_KEY)
    all_transactions += get_internal_transactions(cont_addr, all_transactions, INTERNAL_TRANSACTION_LINK, BLOCK_SCANNER_API_KEY)
    print("Total transactions ->", len(all_transactions))
    tx_arg_details = {}
    slots_and_data = []
    all_slots = []
    for tran in all_transactions:
        try:
            cont_abi = copy.deepcopy(contract_abi)
            contract = w3.eth.contract(abi=cont_abi)
            transac_input = contract.decode_function_input(tran['input'])
        except Exception as e:
            # print("Warning:", str(e))
            continue
        func_name = transac_input[0].fn_name
        if func_name in tx_arg_details:
            tx_arg_details[func_name].append([transac_input, tran['from']])
        else:
            tx_arg_details[func_name] = [[transac_input, tran['from']]]

    try:
        cont_keys_results = key_analysis_result[cont_name]
    except:
        cont_keys_results = []
    print("Extracting data from chain...")
    results = extract_variables_data_from_chain(
        cont_addr, variables_slot_results, all_contracts_dict, contract_abi, all_vars, cont_keys_results, tx_arg_details, slots_and_data, all_slots, w3) 
    print("Done!")
    results = generate_readable_results(cont_addr, results, w3)
    final_results = get_final_results(results)

    print("Length of complete results ->", len(final_results))
    print("Length of Slot and Data ->", len(slots_and_data))
    block = w3.eth.get_block('latest')
    return final_results, results, slot_details, slots_and_data, key_analysis_result, block['number']

