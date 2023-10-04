import copy
from logging import raiseExceptions
import pprint
import itertools
from slither.slither import Slither
from configparser import ConfigParser
from src.ast_parsing.ast_parser import generate_ast
from src.ast_parsing.ast_parser import parse_ast
from web3.auto import Web3
from web3.middleware import geth_poa_middleware
import solcx
from solcx import compile_source
from solc_select import solc_select
from src.state_extraction.slot_calculator import calculate_slots


def print_all(data_list):
    for data in data_list:
        print(data)
    return


def hex_to_declared_type(var_value, var_type, w3):
    if 'int' in var_type or 'uint' in var_type:
        try:
            # var_value = w3.to_int(var_value)
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
            var_value = str(bytearray.fromhex(var_value[2:]).decode())
            var_value = var_value.rstrip('\x00')
    return var_value


def generate_abi(source_code, cont_name):
    compiled_contracts = compile_source(source_code)
    for contract in compiled_contracts:
        curr_cont_name = contract.split(":")[1]
        if cont_name == curr_cont_name:
            cont_abi = compiled_contracts[contract]['abi']
            break
    return cont_abi


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


def read_source_code(contract_name, input_dir):
    input_path = input_dir + contract_name + ".sol"
    f = open(input_path)
    source_code = f.read()
    return source_code


def generate_sol_file(cname, source_code, input_dir):
    path = input_dir + cname + ".sol"
    f = open(path, 'w')
    f.write(source_code)
    f.close()
    return path


def generate_function_cfg(slither, cont_name, func_name):
    req_cfg = []
    for cont in slither.contracts:
        if cont.name == cont_name:
            funcs = cont.functions
            for func in funcs:
                if func.name == func_name:
                    req_cfg = func.nodes
    return req_cfg


# returns name/value of the index from the node expression AST
def expr_helper(stmt):
    if stmt['type'] == 'Identifier':
        return stmt['name']
    elif stmt['type'] == 'MemberAccess':
        return expr_helper(stmt['expression']) + ':m:' + stmt['memberName']
    elif stmt['type'] == 'FunctionCall':
        try:
            func_name = stmt['expression']['name']
        except:
            func_name = 'tou_call'
        return func_name + '()'
    elif stmt['type'] == 'IndexAccess':
        if expr_helper(stmt['index']) == None:
            pass
        if stmt['index']['type'] != 'FunctionCall':
            try:
                return expr_helper(stmt['base']) + ':i:' + expr_helper(stmt['index'])
            except:
                return expr_helper(stmt['base']) + ':i:' + 'tou'
        else:
            try:
                return expr_helper(stmt['base']) + ':i:' + expr_helper(stmt['index'])
            except:
                return expr_helper(stmt['base']) + ':i:' + 'tou'
    elif stmt['type'] == 'TupleExpression':
        tmp = []
        for i in stmt['components']:
            tmp.append(expr_helper(i))
        if len(tmp) == 1:
            return tmp[0]
        return tmp
    elif stmt['type'] == 'NumberLiteral':
        return stmt['number'] + '#'
    elif stmt['type'] == 'BinaryOperation':
        return 'tou'
    elif stmt['type'] == 'UnaryOperation':
        return 'tou'


def get_arg_vars(expr):
    arg_list = []
    split_expr = expr.split(').', 1)
    cont_name = ''
    if len(split_expr) > 1:
        func_expr = split_expr[1]
        temp = split_expr[0].split('(')
        cont_name = temp[0].strip()
    else:
        func_expr = split_expr[0]
    try:
        temp = func_expr.split('(', 1)
        func_name = temp[0]
        arg_expr = temp[1]
    except:
        temp = expr.split('(', 1)
        func_name = temp[0]
        arg_expr = temp[1]
    args_split = arg_expr.split(',')
    if len(args_split) > 1:
        for ind, arg in enumerate(args_split):
            if ind == len(args_split)-1:
                var = arg[:-1]
                arg_list.append(var.strip())
            else:
                var = arg
                arg_list.append(var.strip())
    else:
        arg_list.append(args_split[0][:-1].strip())
    return cont_name, func_name, arg_list


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
        # if userdefined variable is an enum, treat it as elementary type
        try:
            var_struct_data_type = all_contracts_dict[var_struct['typeName']['namePath']]['vars'][0]['dataType']
        except:
            var_struct_data_type = ''
        if var_struct_data_type == 'enum':
            var_dict = {}
            var_dict['type'] = 'ElementaryTypeName'
            var_dict['dataType'] = 'enum'
            var_dict['name'] = var_struct['name']
        else:
            var_dict = {}
            var_dict['type'] = var_struct['typeName']['type']
            var_dict['dataType'] = var_struct['typeName']['namePath']
            try:
                var_dict['typeVars'] = all_contracts_dict[var_struct['typeName']
                    ['namePath']]['vars']
            except:
                var_dict['typeVars'] = []
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
        try:
            lens.append(var_struct['typeName']['length']['number'])
        except:
            lens.append(var_struct['typeName']['length'])
        # iterate over all dimensions of array to get length of each dimension
        while not ('name' in name_struct or 'namePath' in name_struct):
            if 'length' in name_struct:
                try:
                    lens.append(name_struct['length']['number'])
                except:
                    lens.append(name_struct['length'])
            name_struct = name_struct['baseTypeName']
        new_lens = []
        for i in range(1, len(lens)+1):
            new_lens.append(lens[-i])
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
        var_dict['length'] = new_lens
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
        elif node['type'] == 'EnumDefinition':
            var_dict = {}
            var_dict['type'] = 'ElementaryTypeName'
            var_dict['dataType'] = 'enum'
            var_dict['name'] = node['name']
            all_contracts_dict[node['name']] = {'vars': [var_dict]}

    return statevars, all_contracts_dict, all_vars


def get_contract_details(children):
    all_vars = []
    all_contracts_dict = {}
    for contract in children:
        parent = []
        if contract == None:
            continue
        try:
            sub_nodes = contract['subNodes']
        except:
            sub_nodes = []
        if contract['type'] == 'PragmaDirective':
            continue
        state_vars, all_contracts_dict, all_vars = variable_unrolling(
            sub_nodes, all_contracts_dict, all_vars)
        if 'baseContracts' not in contract:
            continue
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
            'vars': state_vars, 'parent': parent, 'type': contract['type']}
    return all_vars, all_contracts_dict


def format_variable_new(var_struct, all_contracts_dict):
    # Takes in a variable, returns the formatted variable according to it's type
    if var_struct['typeName']['nodeType'] == 'ElementaryTypeName':
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['nodeType']
        var_dict['dataType'] = var_struct['typeName']['name']
        var_dict['name'] = var_struct['name']
        return var_dict
    elif var_struct['typeName']['nodeType'] == 'UserDefinedTypeName':
        if 'enum' in var_struct['typeDescriptions']['typeIdentifier']:
            var_dict = {}
            var_dict['type'] = 'ElementaryTypeName'
            var_dict['dataType'] = 'enum'
            var_dict['name'] = var_struct['name']
        else:
            var_dict = {}
            var_dict['type'] = var_struct['typeName']['nodeType']
            try:
                var_dict['dataType'] = var_struct['typeName']['pathNode']['name']
            except:
                var_dict['dataType'] = var_struct['typeName']['name']
            # var_dict['defType'] = all_contracts_dict[var_dict['dataType']]['type']
            var_dict['name'] = var_struct['name']
            try:
                var_dict['typeVars'] = all_contracts_dict[var_dict['dataType']]['vars']
            except:
                var_dict['typeVars'] = []
        return var_dict
    elif var_struct['typeName']['nodeType'] == 'Mapping':
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['nodeType']
        var_dict['keyType'] = var_struct['typeName']['keyType']
        var_dict['valueType'] = var_struct['typeName']['valueType']
        var_dict['name'] = var_struct['name']
        return var_dict
    elif var_struct['typeName']['nodeType'] == 'ArrayTypeName':
        name_struct = var_struct['typeName']['baseType']
        lens = []
        if 'length' in var_struct['typeName']:
            lens.append(var_struct['typeName']['length']['value'])
        else:
            lens.append(None)
        # iterate over all dimensions of array to get length of each dimension
        while not ('name' in name_struct or 'namePath' in name_struct):
            if 'length' in name_struct:
                lens.append(name_struct['length']['value'])
            else:
                lens.append(None)
            name_struct = name_struct['baseType']
        type_struct = name_struct['nodeType']
        
        new_lens = []
        for x in range(1, len(lens)+1):
            new_lens.append(lens[-x])
        
        var_dict = {}
        var_dict['type'] = var_struct['typeName']['nodeType']
        var_dict['dataTypeType'] = type_struct
        var_dict['dataTypeName'] = name_struct['name']
        var_dict['length'] = new_lens
        var_dict['name'] = var_struct['name']
        var_dict['curr'] = -1
        if len(lens) > 1:
            var_dict['dimension'] = 'multi'
        else:
            var_dict['dimension'] = 'single'
        if not (None in lens):
            var_dict['StorageType'] = 'static'
        else:
            var_dict['StorageType'] = 'dynamic'
        return var_dict

def unroll_struct_new(struct, all_contract_dict):
    '''Takes in a struct data type, returns list of variables in the struct'''
    var_lst = []
    for var_struct in struct['members']:
        var_lst.append(format_variable_new(var_struct, all_contract_dict))
    return var_lst


def variable_unrolling_new(subnodes, all_contracts_dict, all_vars):
    statevars = []
    for node in subnodes:
        if node['nodeType'] == "VariableDeclaration":
            if node['stateVariable'] == True:
                try:
                    if node['constant'] == True or node['mutability'] == "immutable":
                        # grab the value if the value is assigned to a variable at compile time
                        try:
                            if 'number' in node['value']['kind'] or 'string' in node['value']['kind']:
                                all_vars.append(
                                    [node['name'], node['typeDescriptions']['typeString'], node['value']['value']])
                                continue
                        except:
                            continue
                    else:
                        statevars.append(format_variable_new(node, all_contracts_dict))            
                except:
                    if node['constant'] == True:
                        # grab the value if the value is assigned to a variable at compile time
                        try:
                            if 'number' in node['value']['kind'] or 'string' in node['value']['kind']:
                                all_vars.append(
                                    [node['name'], node['typeDescriptions']['typeString'], node['value']['value']])
                                continue
                        except:
                            continue
                    else:
                        statevars.append(format_variable_new(node, all_contracts_dict))
        elif node['nodeType'] == 'StructDefinition':
            tmp = unroll_struct_new(node, all_contracts_dict)
            all_contracts_dict[node['name']] = {'vars': tmp, 'type': node['nodeType']}
        elif node['nodeType'] == 'EnumDefinition':
            var_dict = {}
            var_dict['type'] = 'ElementaryTypeName'
            var_dict['dataType'] = 'enum'
            var_dict['name'] = node['name']
            all_contracts_dict[node['name']] = {'vars': [var_dict]}
            
    return statevars, all_contracts_dict, all_vars

def get_contract_details_new(contracts):
    all_vars = []
    all_contracts_dict = {}
    for contract in contracts:
        parent = []
        if contract == None:
            continue
        if contract['nodeType'] == 'PragmaDirective':
            continue
        try:
            sub_nodes = contract['nodes']
        except:
            sub_nodes = []
        state_vars, all_contracts_dict, all_vars = variable_unrolling_new(
            sub_nodes, all_contracts_dict, all_vars)
        # parent contract
        if contract['baseContracts'] != []:
            lst = contract['baseContracts']
            parent_vars = []
            for basecontract in lst:
                parent_cont_name = basecontract['baseName']['name']
                if len(all_contracts_dict) != 0:
                    b_statevars = all_contracts_dict[parent_cont_name]['vars']
                    for var in b_statevars:
                        if type(var) == list:
                            for va in var:
                                if not(va in parent_vars):
                                    parent_vars.append(va)
                        else:
                            if not var in parent_vars:
                                parent_vars.append(var)
            state_vars = parent_vars + state_vars
            parent = contract['baseContracts']
        all_contracts_dict[contract['name']] = {
            'vars': state_vars, 'parent': parent, 'type': contract['nodeType']}
    return all_vars, all_contracts_dict


def handle_func_nodes(in_nodes, node, compiler_version):
    out_nodes = copy.deepcopy(in_nodes)
    tmp = str(node).split()
    keywrd = tmp[0]
    exp = str(node.expression)
    if keywrd == 'NEW':
        var = exp.split(' = ')[0]
        out_nodes.append([var, int(node.node_id)])
        return out_nodes

    elif keywrd == 'EXPRESSION':
        var = exp.split(' = ')[0]  # get left hand operand
        var = var.split('.')[0]  # get classname if member is being accessed
        if var[:8] == 'require(':
            return out_nodes
        vars_used = []
        code = "pragma solidity " + compiler_version + \
            ";\ncontract test3 {   \n    function test () public {\n       " + \
            exp + ";\n    }    \n}"
        try:
            children, _ = generate_ast(code)
        except:
            return out_nodes
        contract = children[1]
        statements = contract['subNodes'][0]['body']['statements'][0]
        stmt = statements
        if 'expression' not in stmt:
            return out_nodes
        if stmt['expression']['type'] == 'BinaryOperation':
            sub_stmt = stmt['expression']['left']
            while 'left' in sub_stmt:
                var_expr = expr_helper(sub_stmt)
                if type(var_expr) == str:
                    vars_used.append(var_expr)
                elif type(var_expr) == list:
                    break
                sub_stmt = sub_stmt['left']
            var_expr = expr_helper(sub_stmt)
            if type(var_expr) == str:
                if ':i:' in var_expr and not [int(node.node_id), var_expr] in reach_analysis.marked_nodes:
                    # to seperate indexes and base variable
                    sepv = var_expr.split(':')
                    if sepv[0] in reach_analysis.maps:
                        reach_analysis.marked_nodes.append(
                            [int(node.node_id), var_expr])
                vars_used.append(var_expr)
            elif type(var_expr) == list:
                for vexp in var_expr:
                    vars_used.append(vexp)
        else:
            return out_nodes
        # updates the old definition with new one
        for var in vars_used:
            for dff in out_nodes:
                if dff[0] == var:
                    ind = out_nodes.index(dff)
                    out_nodes.pop(ind)
                    out_nodes.append([var, int(node.node_id)])
                    break
        return out_nodes
    else:
        return out_nodes


def generate_final_key_approx_results(results):
    final_results = {}
    for rslt in results:
        cont_name = rslt[0]
        if cont_name in final_results:
            func_name = rslt[2]
            if func_name in final_results[cont_name]:
                final_results[cont_name][func_name].append(rslt[3:])
            else:
                final_results[cont_name][func_name] = [rslt[3:]]
        else:
            func_name = rslt[2]
            final_results[cont_name] = {}
            final_results[cont_name][func_name] = [rslt[3:]]
    return final_results

# perform reach analysis on the provided function using its cfg to determine outnode of each code line.
# reach analysis: "data-flow analysis which statically determines which definitions may reach a given point in the code" 
def reach_analysis(cont_name, func_name, slither, state_vars, func_ast_nodes, cont_mappings, compiler_version):
    out_nodes = {}
    in_nodes = {}
    func_nodes = generate_function_cfg(slither, cont_name, func_name)
    unchanged_nodes = generate_function_cfg(slither, cont_name, func_name)
    exec_sequence = []
    reach_analysis.marked_nodes = []
    reach_analysis.maps = cont_mappings[:]
    for f_node in func_nodes:
        out_nodes[f_node.node_id] = []
    if len(func_nodes) > 0:
        for st_var in state_vars:
            out_nodes[func_nodes[0].node_id].append([st_var, 0])
        paramlist = func_ast_nodes['parameters']['parameters']
        for para in paramlist:
            out_nodes[func_nodes[0].node_id].append([para['name'], -1])
        out_nodes[func_nodes[0].node_id].append(['msg.sender', -1])
        out_nodes[func_nodes[0].node_id].append(['msg.value', -1])
        node = unchanged_nodes.pop(0)
        if len(unchanged_nodes) == 0:
            return in_nodes, reach_analysis.marked_nodes
        node_stack = []
        for son in node._sons:
                node_stack.append(son)
        while len(node_stack) > 0:
            node = node_stack.pop()
            exec_sequence.append(node)
            new_sucs = node.sons
            for node in new_sucs:
                if node not in exec_sequence:
                    node_stack.append(node)

    for node in exec_sequence:
        preds = node._fathers
        prev_out_nodes = []
        for pred in preds:
            for nd in out_nodes[pred.node_id]:
                if nd not in prev_out_nodes:
                    prev_out_nodes.append(nd)
        in_nodes[node.node_id] = copy.deepcopy(prev_out_nodes)
        out_nodes[node.node_id] = copy.deepcopy(
            handle_func_nodes(in_nodes[node.node_id], node, compiler_version))
    # if reach_analysis.marked_nodes != []:
    #     print(f"{func_name} -> {reach_analysis.marked_nodes}")
    return in_nodes, reach_analysis.marked_nodes


def back_track(current_contract, func_name, marked_nodes, in_nodes, slither):
    in_nodes = copy.deepcopy(in_nodes)
    func_nodes = generate_function_cfg(slither, current_contract, func_name)
    finals2 = []
    tou_key_list = []
    # marked nodes are those nodes where a contract mapping or its reference was modified
    for node in marked_nodes:
        # node contains node id and mapping_name:i:key
        node_id = node[0]
        map_name_key = node[1].split(':i:')
        mapping_name = map_name_key.pop(0)
        map_keys = map_name_key
        # map_keys_details contains key(s) name and source type id (multiple if mapping is multi dimensional)
        map_keys_details = {}
        for key_idx, m_key in enumerate(map_keys):
            if key_idx not in map_keys_details:
                map_keys_details[key_idx] = []
            if m_key == 'tou':
                map_keys_details[key_idx].append([m_key, 'tou', 'regular'])
                continue
            m_key = m_key.replace('msg:m:sender', 'msg.sender')
            if ':m:' in m_key:
                m_key = m_key.split(':m:')[0]
            # in nodes contains all the definition in each node
            defs = in_nodes[node_id]
            # finding source type of mapping key from in nodes defs
            source_found = False
            for deff in defs:
                if deff[0] == m_key:
                    map_keys_details[key_idx].append(deff + ['regular'])
                    source_found = True
            # if not found mapping key source type is static
            if source_found == False:
                if m_key[-1] == '#':
                    deff = [m_key[:-1], 'x', 'regular']
                else:
                    deff = [m_key, 'tou', 'regular']
                map_keys_details[key_idx].append(deff)
        # if lengths of marked node keys and keys details are not same, then skip the node
        if len(map_keys) != len(map_keys_details):
            raiseExceptions
        map_key_results = {}
        # for back tracking
        for key_idx in map_keys_details:
            for map_key in map_keys_details[key_idx]:
                new_details_added = False
                if map_key[1] == 'tou':
                    tou_key_list.append([func_name, mapping_name, map_key[0], map_key[2]])
                    continue
                key_source_id = map_key[1]
                countt = 0
                # if key_source_id is not equal to global, parameter or argument, then it should be some variable
                while key_source_id != 0 and key_source_id != -1 and key_source_id != 'x':
                    countt += 1
                    if countt > 50:
                        new_details_added = True
                        map_keys_details[key_idx].append([map_key[0], 'tou', 'regular'])
                        break
                    # getting node where value of key was last modified
                    for fn in func_nodes:
                        if fn.node_id == key_source_id:
                            last_mod_node = fn
                    node_details = str(last_mod_node).split()
                    keywrd = node_details[0]
                    exp = last_mod_node.expression  # getting exp of node, to get right hand side value
                    # if right hand side is equal to some variable, get that variable node id from "in_nodes" and repeat loop
                    try:
                        right = exp.expression_right
                        right_type = str(type(right))
                    except:
                        new_details_added = True
                        map_keys_details[key_idx].append([key_val, 'tou', 'regular'])
                        break
                    if 'identifier' in right_type:
                        new_var = str(right.value)
                        new_var = new_var.replace('msg:m:sender', 'msg.sender')
                        defs = in_nodes[key_source_id]
                        def_found = False
                        for deff in defs:
                            if deff[0] == new_var and def_found == False:
                                key_source_id = deff[1]
                                map_key[0] = new_var
                                def_found = True
                            elif deff[0] == new_var and def_found == True:
                                map_keys_details[key_idx].append([new_var, deff[1], 'regular'])
                    elif 'literal' in right_type:
                        key_val = str(right.value)
                        break
                    else:
                        new_details_added = True
                        map_keys_details[key_idx].append([map_key[0], 'tou', 'others'])
                        break
                if new_details_added == True:
                    continue
                key_pos_in_arg = -1
                if key_source_id == -1:
                    keywrd = 'Argument'
                    defs = in_nodes[func_nodes[1].node_id]
                    for deff in defs:
                        if deff[1] == -1:
                            key_pos_in_arg += 1
                            if deff[0] == map_key[0]:
                                break
                    key_val = key_source_id
                elif key_source_id == 0:
                    keywrd = 'Global'
                    key_val = key_source_id
                elif key_source_id == 'x':
                    keywrd = 'Static'
                    key_val = map_key[0]
                # name of mapping key, name of key variable, value of key (in case key type is static or new),
                # key type and  position of key in func arg
                if key_idx not in map_key_results:
                    map_key_results[key_idx] = []
                map_key_results[key_idx].append([mapping_name, map_key[0],
                        key_val, keywrd, key_pos_in_arg, map_key[2]])

        if len(map_key_results) != len(map_keys_details):
            continue
        keys_list = []
        for key_idx in map_key_results:
            keys_list.append(map_key_results[key_idx])
        all_combinations = list(itertools.product(*keys_list))
        for comb in all_combinations:
            comp_reslt = []
            for key_reslt in list(comb):
                comp_reslt += key_reslt
            if comp_reslt != []:
                finals2.append([func_name] + comp_reslt)    
    return finals2, tou_key_list



def key_approx_analysis(contract_name, contract, state_vars, func_name, slither, functions, cont_mappings, results, compiler_version):
    fbody_found = False
    for ind, func in enumerate(functions[contract]):
        if func['name'] == func_name:
            func_body = func
            functions[contract].pop(ind)
            fbody_found = True
            break
    if fbody_found == False:
        print("func:", func_name, "ast not found!")
    if func_body == None:
        raise ValueError
    in_nodes, marked_nodes = reach_analysis(contract, func_name,
        slither, state_vars, func_body, cont_mappings, compiler_version)
    function_backtrack_results, tou_keys = back_track(contract,
        func_name, marked_nodes, in_nodes, slither)

    for result in function_backtrack_results:
        results.append([contract_name, contract] + result)
        
    return results, functions, tou_keys


def extract_slot_details(variables_slot_results):
    keys_type = {}
    slot_details = []
    for var_ast in variables_slot_results:
        slot = "slot "+str(var_ast['slot'])+ " - "
        if var_ast['type'] == 'Mapping':
            var = var_ast['type'].lower()+" "+var_ast['name']
            keys_type[var] = []
            while 'valueType' in var_ast:
                keys_type[var].append(var_ast['keyType']['name'])
                var_ast = var_ast['valueType']
            for key in var_ast:
                if 'name' in key:
                    value = var_ast[key]
            for key in keys_type[var]:
                var+="["+key+"]"
            var_details = var+" = "+value+";"
        elif var_ast['type'] == "ElementaryTypeName":
            var_details = var_ast['dataType']+" "+var_ast['name']+";"
        elif var_ast['type'] == "ArrayTypeName":
            dim = len(var_ast['length'])
            bracket=""
            for i in range(dim):
                bracket+="[]"
            var_details = var_ast["dataTypeName"]+" "+bracket+" "+var_ast['name']+";"
        elif var_ast['type'] == "UserDefinedTypeName":
            var_details = var_ast['dataType']+" "+var_ast['name']+";"

        slot_details.append(slot+var_details)
    return slot_details


def key_approx_analyzer(contract_name, source_code, compiler_version):
    config = ConfigParser()
    config.read("config.ini")

    input_dir = config.get('directories', 'contract_directory')
    code_file = generate_sol_file(contract_name, source_code, input_dir)
    if compiler_version != '':
        children, _ = generate_ast(source_code)
        switch_compiler(compiler_version)
    else:
        children, compiler_version = generate_ast(source_code)
        switch_compiler(compiler_version)
    children.pop(0)
    all_contracts_details, all_functions_ast = parse_ast(children)
    slither = Slither(code_file)

    results = []
    func_calls_analyzed = []
    all_tou_keys = []
    all_funcs_names = [] # to ignore functions like require
    functions_ast = {}
    func_names = {} # saves all functions for each contract
    # extracting all function and performing reach analysis and back tracking on each function node
    for cntrct in all_contracts_details:
        state_vars = all_contracts_details[cntrct]['vars']
        func_names[cntrct] = all_contracts_details[cntrct]['func']
        functions_ast[cntrct] = all_contracts_details[cntrct]['fbody']
        all_funcs_names += list(all_functions_ast[cntrct].keys())
        for fn in func_names[cntrct]:
            if fn not in all_funcs_names:
                all_funcs_names.append(fn)
        mappings = [mapp[0] for mapp in all_contracts_details[cntrct]['maps']]
        for f_name in func_names[cntrct]:
            func_calls_analyzed+=[f_name]
            results, functions_ast, tou_keys = key_approx_analysis(
                contract_name, cntrct, state_vars, f_name, slither, functions_ast, mappings, results, compiler_version)
            all_tou_keys += tou_keys

    try:
        compiled_sol = compile_source(source_code)
        cont_ast = compiled_sol['<stdin>:'+contract_name]['ast']['nodes']
        all_vars, all_contracts_dict = get_contract_details_new(cont_ast)
    except Exception as e:
        print("Warning - in get_contract_details_new ---", e)
        children, compiler_version = generate_ast(source_code)
        children.pop(0)
        all_vars, all_contracts_dict = get_contract_details(children)

    _, variables_slot_results = calculate_slots(
        all_contracts_dict[contract_name]['vars'], -1, all_contracts_dict)

    slot_details = extract_slot_details(variables_slot_results)

    print("\nThe slot layout of the provided smart contract is as follow:\n")
    print_all(slot_details)

    state_vars = {}
    for cont in all_contracts_dict:
        state_vars[cont] = all_contracts_dict[cont]['vars']
    all_cont_func = {}
    for cont in all_functions_ast:
        all_cont_func[cont] = []
        for func in all_functions_ast[cont]:
            all_cont_func[cont].append(func)

    complete_analysis_results = {}
    complete_analysis_results['state_vars'] = state_vars
    complete_analysis_results['all_funcs'] = all_cont_func
    complete_analysis_results['func_call_analyzed'] = func_calls_analyzed
    complete_analysis_results['tou_keys'] = all_tou_keys
    complete_analysis_results['slot_details'] = slot_details
    complete_analysis_results['all_contracts_dict'] = all_contracts_dict
    complete_analysis_results['variables_slot_results'] = variables_slot_results
    complete_analysis_results['all_vars'] = all_vars
    
    final_results = generate_final_key_approx_results(results)

    return final_results, complete_analysis_results


def get_slot_details(contract_name, source_code, compiler_version):
    config = ConfigParser()
    config.read("config.ini")

    if compiler_version != '':
        switch_compiler(compiler_version)
    else:
        _, compiler_version = generate_ast(source_code)
        switch_compiler(compiler_version)
        
    try:
        compiled_sol = compile_source(source_code)
        cont_ast = compiled_sol['<stdin>:'+contract_name]['ast']['nodes']
        _, all_contracts_dict = get_contract_details_new(cont_ast)
    except Exception as e:
        print("Warning - in get_contract_details_new ---", str(e))
        children, compiler_version = generate_ast(source_code)
        children.pop(0)
        _, all_contracts_dict = get_contract_details(children)

    _, variables_slot_results = calculate_slots(
        all_contracts_dict[contract_name]['vars'], -1, all_contracts_dict)
    slot_details = extract_slot_details(variables_slot_results)
        
    return slot_details
