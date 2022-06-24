import json
from solidity_parser import parser as sol_parser
from configparser import ConfigParser

def generate_sol_file(cont_name, source_code, output_dir):
    output_path = output_dir + cont_name + '-new.sol'
    file = open(output_path, 'w')
    file.write(source_code)
    file.close()
    return

def parse_base_contract(base_cont_lst, all_contracts, state_vars):
    for base_contract in base_cont_lst:
        tmp = base_contract['baseName']['namePath']
        b_state_vars = all_contracts[tmp]['vars']
        for var in b_state_vars:
            if type(var) == list:
                var_list = var
                state_vars = state_vars + [v for v in var_list]
            else:
                state_vars.append(var)
    return state_vars

def get_all_variables(source_unit, all_contracts, is_new_contract:bool):
    children = source_unit['children']
    children.pop(0)
    vars = []
    inherit_count = 0
    all_contracts_current = {}

    for contract in children:
        if contract['type'] == 'PragmaDirective':
            continue
        try:
            sub_nodes = contract['subNodes']
        except:
            sub_nodes = []
        state_vars = []
        for definition in sub_nodes:
            if definition['type'] == 'StateVariableDeclaration':
                vars = definition['variables']
                for var in vars:
                    var["Inheritance"] = inherit_count
                    state_vars.append(var)
        if contract['baseContracts'] != []:
            base_cont_lst = contract['baseContracts']
            if is_new_contract == True:
                state_vars = parse_base_contract(base_cont_lst, all_contracts, state_vars)
            else:
                state_vars = parse_base_contract(base_cont_lst, all_contracts_current, state_vars)        
        tmp_state_vars = state_vars[:]
        for state_var in range(0, len(tmp_state_vars)):
            tmp_state_vars[state_var] = json.dumps(tmp_state_vars[state_var])
        tmp_state_vars = list(set(tmp_state_vars))
        for state_var in range(0, len(tmp_state_vars)):
            state_vars[state_var] = json.loads(tmp_state_vars[state_var])
        if state_vars != []:
            inherit_count += 1
        all_contracts_current[contract['name']] = {'vars': state_vars}
    return all_contracts_current


def upgrade_contract(cont_name, old_source_code, new_source_code, cont_state):
    config = ConfigParser()
    config.read("config.ini")
    output_dir = config.get('directories', 'upgrade_directory')
    source_unit_old = sol_parser.parse(old_source_code) 
    all_contracts_old = {}
    all_contracts_old = get_all_variables(source_unit_old, all_contracts_old, is_new_contract=False)
    source_unit_new = sol_parser.parse(new_source_code) 
    all_contracts_new = get_all_variables(source_unit_new, all_contracts_old, is_new_contract=True)
    intialized_new_code = str(new_source_code).split('\n')
    cont_found = False
    cont_ind = 0
    constructor_ind = 0
    for line_num in range(0,len(intialized_new_code)):
        code_line = intialized_new_code[line_num]
        if 'contract ' + cont_name in code_line:
            cont_found = True
            cont_ind = line_num
            break
    for var in all_contracts_new[cont_name]['vars']:
        tmp = var['name'] 
        for line_num in range(cont_ind, len(intialized_new_code)):
            code_line = intialized_new_code[line_num]        
            if(('constructor()' in code_line or 'function ' + cont_name + '(' in code_line or 'constructor (' in code_line) and cont_found):
                constructor_ind = line_num
                break       
        for index in range(constructor_ind-1, len(intialized_new_code)):
            code_line = intialized_new_code[index] 
            if tmp + ' = ' in code_line:
                all_contracts_new[cont_name]['vars'].remove(var)

    state_lst = []
    for var_new in all_contracts_new[cont_name]['vars']:
        var_new_name = var_new['name']
        for line_num in cont_state:
            split_var = line_num[0].split(':')
            if var_new_name == split_var[0]:
                if line_num[1] == 'string':
                    line_num[2] = '"' + line_num[2] + '"'
                if line_num[1] == 'address':
                    line_num[2] = "0x" + line_num[2][-40:]
                if len(split_var) > 1:
                    varr = split_var.pop(0)
                    st = ''
                    for vars in range(1, len(split_var), 2):
                        st = st + '[' + split_var[vars] + ']'
                    state_lst.append(varr + st + '=' + str(line_num[2]) + ';\n')
                else:
                    state_lst.append(var_new_name + '=' + str(line_num[2]) + ';\n')

    contract_found = False
    contructor_found = False
    for line_num in range(0, len(intialized_new_code)):
        definition = intialized_new_code[line_num]
        if 'contract ' + cont_name in definition:
            contract_found = True
        if ('constructor()' in definition or 'function ' + cont_name + '(' in definition) and contract_found:
            contructor_found = True
            break
    if contructor_found:
        ind = line_num
        for st in state_lst:
            intialized_new_code.insert(ind+1, '\t' + st)
    else:
        ind = len(intialized_new_code) - 1
        while True:
            ind = ind - 1
            if intialized_new_code[ind].strip() == '}':
                break
        ind = ind - 1
        intialized_new_code.insert(ind, '}')
        for st in state_lst:
            intialized_new_code.insert(ind, '\t' + st)
        intialized_new_code.insert(ind, '\tconstructor() public{')
    new_contract_source_code = '\n'.join(intialized_new_code)
    generate_sol_file(cont_name, new_contract_source_code, output_dir)
    return new_contract_source_code
