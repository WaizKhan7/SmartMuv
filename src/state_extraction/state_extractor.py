import requests
import collections
import math
from hexbytes import HexBytes
from src.key_approx_analysis.key_approx_analyzer import key_approx_analyzer
from src.state_extraction.slot_calculator import calculate_slots
import warnings
import time
from solc import compile_source
from src.ast_parsing.ast_parser import generate_ast
from web3.auto import Web3
from configparser import ConfigParser
import copy
warnings.filterwarnings("ignore")

def generate_readable_results(results, w3):
    for var in results:
        if ('int' in var[1] and len(var) > 3) or 'uint' in var[1]:
            try:
                var[2] = w3.toInt(var[2])
            except:
                var[2] = int(var[2])
        elif 'string' in var[1]:
            try:
                var[2] = var[2].decode("utf-8").split(u'\x00')[0]
            except:
                pass
        else:
            try:
                var[2] = w3.toHex(var[2])
            except:
                var[2] = w3.toHex(w3.toBytes(hexstr=var[2]))
    return results

def generate_abi(source_code, cont_name):
    compiled_contracts = compile_source(source_code)
    for contract in compiled_contracts:
        curr_cont_name = contract.split(":")[1]
        if cont_name == curr_cont_name:
            cont_abi = compiled_contracts[contract]['abi']
            break
    return cont_abi

def unroll_struct(struct, all_contract_dict):
    '''Takes in a struct data type, returns list of variables in the struct'''
    var_lst = []
    for var_struct in struct['members']:
        var_lst.append(format_variable(var_struct, all_contract_dict))
    return var_lst

def format_variable(var_struct, all_contracts_dict):
    '''Takes in a variable, returns the formatted variable according to it's type'''
    if var_struct['typeName']['type'] == 'ElementaryTypeName':
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['type']
        var_dict['dataType'] = var_struct['typeName']['name']
        var_dict['name'] = var_struct['name']
        return var_dict
    elif var_struct['typeName']['type'] == 'UserDefinedTypeName':
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['type']
        var_dict['dataType'] = var_struct['typeName']['namePath']
        var_dict['typeVars'] = all_contracts_dict[var_struct['typeName']['namePath']]['vars']
        var_dict['name'] = var_struct['name']
        return var_dict
    elif var_struct['typeName']['type'] == 'Mapping':
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['type']
        var_dict['keyType'] = var_struct['typeName']['keyType']
        var_dict['valueType'] = var_struct['typeName']['valueType']
        var_dict['name'] = var_struct['name']
        return var_dict
    elif var_struct['typeName']['type'] == 'ArrayTypeName':
        name_struct = var_struct['typeName']['baseTypeName']
        lens = []
        # iterate over all dimensions of array to get length of each dimension
        while not ('name' in name_struct or 'namePath' in name_struct):
            if 'length' in name_struct:
                lens.append(name_struct['length'])
            name_struct = name_struct['baseTypeName']

        lens.append(var_struct['typeName']['length'])
        type_struct = name_struct['type']
        var_dict = {}

        if 'name' in name_struct:
            name_struct = name_struct['name']
            type_struct = 'ElementaryTypeName'
        else:
            name_struct = name_struct['namePath']
            type_struct = 'UserDefinedTypeName'

        var_dict['type'] = var_struct['typeName']['type']
        var_dict['dataTypeType'] = type_struct
        var_dict['dataTypeName'] = name_struct
        var_dict['length'] = lens
        var_dict['name'] = var_struct['name']
        var_dict['curr'] = -1
        if len(lens) > 1:
            var_dict['dimension'] = 'multi'
        else:
            var_dict['dimension'] = 'single'
        if not(None in lens):
            var_dict['StorageType'] = 'static'
        else:
            var_dict['StorageType'] = 'dynamic'
        return var_dict


def variable_unrolling(subnodes, all_contracts_dict, all_vars):
    statevars = []
    for node in subnodes:
        if node['type'] == 'StateVariableDeclaration':
            vars = node['variables']
            for variable in vars:
                # grab the value if the value is assigned to a variable at compile time
                if variable['isDeclaredConst'] == True:
                    if 'value' in variable['expression']:
                        all_vars.append(
                            [variable['name'], variable['typeName']['name'], variable['expression']['value']])
                    elif 'number' in variable['expression']:
                        all_vars.append(
                            [variable['name'], variable['typeName']['name'], variable['expression']['number']])
                    continue
                statevars.append(format_variable(variable, all_contracts_dict))
        elif node['type'] == 'StructDefinition':
            tmp = unroll_struct(node, all_contracts_dict)
            all_contracts_dict[node['name']] = {'vars': tmp}
    return statevars, all_contracts_dict, all_vars

def extract_elementry_variables(ord_slots, cont_addr, w3):

    var_lst = []
    for key in ord_slots.keys():
        vars1 = ord_slots[key]
        val = w3.eth.getStorageAt(w3.toChecksumAddress(cont_addr), key)
        bytes_used = 0
        byte_str = val
        sep_bytes = [byte_str[i:i+2] for i in range(0, len(byte_str), 2)]

        if len(sep_bytes) == 1:
            sep_bytes[0] = HexBytes(HexBytes('0x00')+HexBytes(sep_bytes[0]))
        sep_bytes = [HexBytes('0x0000')] * (16 - len(sep_bytes))+sep_bytes
        if len(vars1) > 1:
            sep_bytes.reverse()
            for var in vars1:
                tmp = []
                for j in range(math.ceil(bytes_used/2), math.ceil((bytes_used+var['bytes'])/2)):
                    try:
                        tmp.append(sep_bytes[j])
                    except Exception as e:
                        print(e)
                bytes_used += var['bytes']
                tmp.reverse()
                var_lst.append([var['name'], var['dataType'],
                            b''.join(tmp), var['bytes']]) 
        else:
            var_lst.append([vars1[0]['name'], vars1[0]['dataType'],
                        b''.join(sep_bytes), vars1[0]['bytes']])
    return var_lst

def extract_user_defined_vars_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3):
    try:
        all_vars = extract_variables_data_from_chain(
            cont_addr, var['object']['typeVars'], all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3)
    except:
        all_vars = extract_variables_data_from_chain(
            cont_addr, var['typeVars'], all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3)
    return all_vars

def extract_array_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3):

    f = w3.soliditySha3(['uint256'], [var['slot']])
    levels = len(var['length'])  # levels of array
    tmpc = []
    for key_details in range(0, levels-1):
        if key_details == 0:
            tmpc = [['', var['slot']]]
        tmp_lst = []
        for q in range(0, len(tmpc)):
            slot = tmpc[q][1]
            g = w3.toInt(w3.eth.getStorageAt(
                w3.toChecksumAddress(cont_addr), slot))
            f = w3.toInt(w3.soliditySha3(['uint256'], [slot]))

            for k in range(0, g):
                loc = k+f
                tmp_lst.append([tmpc[q][0]+str(k)+':', loc])

        tmpc = tmp_lst[:]

    c = 0
    for key_details in tmpc:
        g = w3.toInt(w3.eth.getStorageAt(
            w3.toChecksumAddress(cont_addr), key_details[1]))
        f = w3.toInt(w3.soliditySha3(['uint256'], [key_details[1]]))
        var_dict = {}
        var_dict['type'] = 'ArrayTypeName'
        var_dict['dataTypeType'] = var['dataTypeType']
        var_dict['dataTypeName'] = var['dataTypeName']
        var_dict['length'] = [{'type': 'NumberLiteral', 'number': str(g)}]
        var_dict['name'] = var['name']+':'+str(c)
        c = c+1
        var_dict['curr'] = -1
        var_dict['dimension'] = 'single'
        var_dict['StorageType'] = 'static'

        _, slot_results = calculate_slots([var_dict], f-1, all_contracts)
        all_vars = extract_variables_data_from_chain(cont_addr, slot_results, all_contracts, contract_abi,
                            all_vars, key_approx_results, transacs, w3)
    return all_vars

def extract_mapping_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3):
    keys = []
    keys_detail_list = var
    func_lst = []
    while 'valueType' in keys_detail_list:
        keys.append(keys_detail_list['keyType'])
        keys_detail_list = keys_detail_list['valueType']
    statics = []
    if len(key_approx_results) != 0:
        for func_name in key_approx_results.keys():
            keys_detail_list = key_approx_results[func_name]
            for key_details in keys_detail_list:
                if key_details[0] == var['name']:
                    split_array = [key_details[q:q + 5] for q in range(0, len(key_details), 5)]
                    bol = True
                    for ar in split_array:
                        if not (ar[3] == 'Static'):
                            bol = False
                    if bol:
                        statics.append([func_name, key_details])
                    else:
                        func_lst.append([func_name, key_details])
    possible_keys = []
    level = 1
    val = var['valueType']
    while 'keyType' in val:
        level += 1
        val = val['valueType']

    for fun in statics:
        tmp_lst = []
        # variables that are modifying the keys
        split_array = [fun[1][q:q + 5] for q in range(0, len(fun[1]), 5)]
        while len(split_array) != 0:
            dum = []
            for lev in range(0, level):
                ar = split_array.pop(0)
                ar.pop(0)
                dum.append([ar[1], 'address'])
            tmp_lst.append(dum)

        if tmp_lst != []:
            possible_keys.append(tmp_lst)
    c = 0
    for fun in func_lst:
        for tran in transacs:
            try:
                cont_abi = copy.deepcopy(contract_abi)
                contract = w3.eth.contract(abi=cont_abi)
                keys_detail_list = contract.decode_function_input(tran['input'])
            except:
                continue
            c = c+1
            if keys_detail_list[0].fn_name == fun[0]:
                # input types of a function
                tabi = keys_detail_list[0].abi['inputs']
                tabi.append({'name': 'msg.sender', 'type': 'address'})
                inputs = keys_detail_list[1]
                inputs['msg.sender'] = tran['from']
                tmp_lst = []
                # variables that are modifying the keys
                split_array = [fun[1][q:q + 5]
                            for q in range(0, len(fun[1]), 5)]
                while len(split_array) != 0:
                    dum = []
                    for lev in range(0, level):
                        ar = split_array.pop(0)
                        ar.pop(0)
                        for key in inputs.keys():
                            if(key == tabi[ar[3]]['name']):
                                dum.append(
                                    [inputs[tabi[ar[3]]['name']], tabi[ar[3]]['type']])
                                break

                    tmp_lst.append(dum)
                if tmp_lst != []:
                    possible_keys.append(tmp_lst)
    map_slots = []
    for item in possible_keys:
        for sub in item:
            placeholder = []
            for lev in range(0, level):
                if sub[lev][1] == 'address':
                    placeholder.append(
                        [w3.toInt(hexstr=sub[lev][0]), sub[lev][0]])

        slot = var['slot']
        for vr in placeholder:
            f = w3.soliditySha3(['uint256', 'uint256'], [vr[0], slot])
            slot = w3.toInt(f)
        if [w3.toInt(f), vr[1]] in map_slots:
            continue
        map_slots.append([w3.toInt(f), vr[1]])
    val = var['valueType']
    while 'valueType' in val:
        val = val['valueType']
    p = 0
    for slot in map_slots:
        var_dict = {}
        var_dict['type'] = val['type']
        if val['type'] == 'ElementaryTypeName':
            var_dict['dataType'] = val['name']
        elif val['type'] == 'UserDefinedTypeName':
            var_dict['dataType'] = var['namePath']
            var_dict['typeVars'] = all_contracts[var['typeName']['namePath']]['vars']
        var_dict['name'] = var['name']+":key:"+slot[1]
        _, slot_results = calculate_slots([var_dict], slot[0] - 1, all_contracts)
        p = p + 1
        all_vars = extract_variables_data_from_chain(cont_addr, slot_results, all_contracts, contract_abi,
                            all_vars, key_approx_results, transacs, w3)
    return all_vars

def extract_variables_data_from_chain(cont_addr, vars_slot, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3):
    '''
    Take state variables and return their value
            Parameters:
                    cont_addr(str): Address of the contract
                    vars_slot(list): Holds list of all variables and slot details
                    all_contracts(list): Holds details of all contracts
                    contract_abi(list): ABI of the contract
                    all_vars(str): Holds values of extracted variable
                    key_approx_results(list): Holds results of key approximation analysis
                    transacs(list): List of all transactions of the contract
                    w3(object): web3 object for ethereum archive node connection
            Returns:
                    returns all_vars list with values of variables added 
    '''
    group = {}
    for var in vars_slot:
        if var['type'] == 'ElementaryTypeName':
            if not(var['slot'] in group):
                group[var['slot']] = [var]
            else:
                group[var['slot']].append(var)
    ord_slots = collections.OrderedDict(sorted(group.items()))
    var_lst = extract_elementry_variables(ord_slots, cont_addr, w3)
    all_vars = all_vars + [var for var in var_lst]
    for var in vars_slot:
        if var['type'] == 'UserDefinedTypeName':
            all_vars = extract_user_defined_vars_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3)
        if var['type'] == 'ArrayTypeName':
            all_vars = extract_array_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3)
        if var['type'] == 'Mapping':
            all_vars = extract_mapping_data(cont_addr, var, all_contracts, contract_abi, all_vars, key_approx_results, transacs, w3)
    return all_vars

def retrieve_transactions(TRANSACTION_LINK, cont_addr, page, API_KEY):
    try:
        req = requests.get(TRANSACTION_LINK.format(cont_addr, page, API_KEY))
        return req
    except requests.exceptions.ConnectionError:
        print("Connection refused")
        if req.json()['status'] == '0':
            time.sleep(3600)
            retrieve_transactions(cont_addr, page, API_KEY)

def get_transactions(cont_addr, all_transactions, TRANSACTION_LINK, ETHERSCAN_API_KEY):
    page = 0
    while True:
        page = page+1
        req = retrieve_transactions(TRANSACTION_LINK, cont_addr, page, ETHERSCAN_API_KEY)
        try:
            data = req.json()
        except:
            pass
        if data['result'] != None:
            for transac in data['result']:
                all_transactions.append(transac)
            if data['message'] == 'No transactions found':
                break
    return all_transactions

def retrieve_internal_transactions(INTERNAL_TRANSACTION_LINK, add, page, API_KEY):
    try:
        req = requests.get(INTERNAL_TRANSACTION_LINK.format(add, page, API_KEY))
        return req
    except requests.exceptions.ConnectionError:
        print("Connection refused")
        if req.json()['status'] == '0':
            time.sleep(3600)
            retrieve_internal_transactions(add, page, API_KEY)

def get_internal_transactions(cont_addr, all_transactions, INTERNAL_TRANSACTION_LINK, ETHERSCAN_API_KEY):
    page = 0
    while True:
        page = page + 1
        req = retrieve_internal_transactions(INTERNAL_TRANSACTION_LINK, cont_addr, page, ETHERSCAN_API_KEY)
        if req != None:
            data = req.json()
            if data['result'] != None:
                for transac in data['result']:
                    all_transactions.append(transac)
                if data['message'] == 'No transactions found':
                    break
    return all_transactions

def get_contract_details(children):
    all_vars = []
    all_contracts_dict = {}
    for contract in children:
        parent = []
        try:
            sub_nodes = contract['subNodes']
        except:
            sub_nodes = []
        if contract['type'] == 'PragmaDirective':
            continue
        state_vars, all_contracts_dict, all_vars = variable_unrolling(
            sub_nodes, all_contracts_dict, all_vars)
        if contract['baseContracts'] != []:
            lst = contract['baseContracts']
            tmpls = []
            for basecontract in lst:
                tmp = basecontract['baseName']['namePath']
                if len(all_contracts_dict) != 0:
                    b_statevars = all_contracts_dict[tmp]['vars']
                    for var in b_statevars:
                        if type(var) == list:
                            for va in var:
                                if not(va in tmpls):
                                    tmpls.append(va)
                        else:
                            if not var in tmpls:
                                tmpls.append(var)
            state_vars = tmpls + state_vars
            parent = contract['baseContracts']
        all_contracts_dict[contract['name']] = {
            'vars': state_vars, 'parent': parent}
    return all_vars, all_contracts_dict

def get_variables_slot(cont_name, source_code):
    '''Takes in a source file path, contract name, and address of contract, returns list of variable with their slot details'''
    children, _ = generate_ast(source_code)
    children.pop(0)
    _, all_contracts_dict = get_contract_details(children)

    _, variables_slot_results = calculate_slots(
        all_contracts_dict[cont_name]['vars'], -1, all_contracts_dict)
    return variables_slot_results


def extract_contract_state(cont_name, source_code, cont_addr):
    '''Takes in a source file path, contract name, and address of contract, returns list of variable with extracted values and current block number'''
    config = ConfigParser()
    config.read("config.ini")
    INFURA_NODE_LINK = config.get('infura', 'infura_node_link')
    INFURA_PID = config.get('infura', 'infura_pid')
    ETHERSCAN_API_KEY = config.get('etherscan', 'etherscan_api_key')
    TRANSACTION_LINK = config.get('etherscan', 'transaction_link')
    INTERNAL_TRANSACTION_LINK = config.get('etherscan', 'internal_transaction_link')
    w3 = Web3(Web3.HTTPProvider(INFURA_NODE_LINK + INFURA_PID))
    all_transactions = []

    children, _ = generate_ast(source_code)
    children.pop(0)
    all_vars, all_contracts_dict = get_contract_details(children)
    key_analysis_results = key_approx_analyzer(cont_name, source_code)
    contract_abi = generate_abi(source_code, cont_name)
    _, variables_slot_results = calculate_slots(
        all_contracts_dict[cont_name]['vars'], -1, all_contracts_dict)
    try:
        cont_keys_results = key_analysis_results[cont_name]
    except:
        cont_keys_results = []
        print("No Mappings Found!")
    all_transactions = get_transactions(cont_addr, all_transactions, TRANSACTION_LINK, ETHERSCAN_API_KEY)
    all_transactions = get_internal_transactions(cont_addr, all_transactions, INTERNAL_TRANSACTION_LINK, ETHERSCAN_API_KEY)
    results = extract_variables_data_from_chain(
        cont_addr, variables_slot_results, all_contracts_dict, contract_abi, all_vars, cont_keys_results, all_transactions, w3)   
    results = generate_readable_results(results, w3)
    block = w3.eth.getBlock('latest')
    return results, block['number']
