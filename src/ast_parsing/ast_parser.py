from solidity_parser import parser as sol_parser

def generate_ast(code):
    source_unit = sol_parser.parse(code)
    children = source_unit['children']
    try:
        compiler_version = children[0]['value']
    except:
        compiler_version = ''
    return children, compiler_version

def check_ast_nodes(sub_nodes, definition, functions, variables, mappings):
    statements = sub_nodes['statements']
    for statement in statements:
        if statement == ';' or statement == None:
            continue
        if statement['type'] == 'ExpressionStatement':
            functions, variables, mappings = check_mapping(
                statement, definition, functions, variables, mappings)
        elif statement['type'] == 'IfStatement':
            functions, variables, mappings = check_if_stmt(
                statement, definition, functions, variables, mappings)
        elif statement['type'] == 'ForStatement':
            functions, variables, mappings = check_ast_nodes(
                statement['body'], definition, functions, variables, mappings)
    return functions, variables, mappings


def check_mapping(statement, definition, functions, variables, mappings):
    if statement['expression']['type'] == 'BinaryOperation':
        if '=' in statement['expression']['operator'] and statement['expression']['operator'] != '==':
            if statement['expression']['left']['type'] == 'IndexAccess':
                tmp = statement['expression']['left']
                while 'base' in tmp['base']:
                    tmp = tmp['base']
                # mappings contains mapping name and key type, extracting mapping names from the list
                mapp_names = [x[0] for x in mappings]
                if tmp['base']['name'] in mapp_names:
                    if definition not in functions:
                        functions.append(definition)
                tmp = statement['expression']['left']
                tmp_var_list = []
                while 'index' in tmp:
                    try:
                        tmp_var_list.append(tmp['index']['name'])
                    except:
                        a = tmp['index']['expression']['name']
                        b = tmp['index']['memberName']
                        tmp_var_list.append(a + '.' + b)
                    tmp = tmp['base']
                tmp_var_list.reverse()
                tmp_var_list.insert(0, definition['name'])
                if len(tmp_var_list) > 0:
                    variables.append(tmp_var_list)
    return functions, variables, mappings


def check_if_stmt(statement, definition, functions, variables, mappings):
    statements = statement['TrueBody']
    functions, variables, mappings = check_ast_nodes(
        statements, definition, functions, variables, mappings)
    statements = statement['FalseBody']

    if statements == None:
        return
    functions, variables, mappings = check_ast_nodes(
        statements, definition, functions, variables, mappings)
    return functions, variables, mappings


def parse_ast(children):
    all_contracts_details = {}
    variables = []
    state_vars = []
    cont_names = []
    mappings = []
    cont_functions = {}
    for contract in children:
        if contract == None:
            continue
        if contract['type'] == "ContractDefinition":
            cont_names.append(contract['name'])
        else:
            continue
        functions = []
        func_names = []
        func_var = []
        parents = []
        all_functions = {}
        try:
            sub_nodes = contract['subNodes']
        except:
            sub_nodes = []
        for definition in sub_nodes:
            #print(definition['type'])
            if definition['type'] == 'StateVariableDeclaration':
                dec_vars = definition['variables']
                state_vars = state_vars + [var['name'] for var in dec_vars]
            try:
                if definition['type'] == 'StateVariableDeclaration':
                    if definition['variables'][0]['typeName']['type'] == 'Mapping':
                        key_type = definition['variables'][0]['typeName']['keyType']['name']
                        mappings.append([definition['variables'][0]['name'], key_type])
            except:
                pass
            if definition['type'] == "FunctionDefinition":
                all_functions[definition['name']] =  definition
                functions.append(definition)
            try:
                statements = definition['body']
                if statements != []:
                    functions, variables, mappings = check_ast_nodes(
                        statements, definition, functions, variables, mappings)
            except KeyError:
                continue
            except:
                pass      
        # replaces duplicate names of functions
        for func in functions:
            if func['name'] not in func_names:
                if func['name'] == None:
                    func['name'] = 'constructor'
                func_names.append(func['name'])
        # replaces duplicate func, var pairs
        for var in variables:
            if var not in func_var:
                func_var.append(var)
        if 'baseContracts' in contract:
            if contract['baseContracts'] != []:
                parents = contract['baseContracts']
                for base_contract in contract['baseContracts']:
                    tmp = base_contract['baseName']['namePath']
                    if tmp not in cont_names:
                        continue                
                    base_vars = all_contracts_details[tmp]['vars']
                    base_funcs = all_contracts_details[tmp]['fbody']
                    for func in base_funcs:
                        if func not in functions:
                            functions.append(func)
                        if func['name'] not in func_names:
                            if func['name'] == None:
                                func['name'] = 'constructor'
                            func_names.append(func['name'])
                    # func_names = func_names + [func['name'] for func in base_funcs ]
                    for var in base_vars:
                        if type(var) == list:
                            var_list = var
                            for v in var_list:
                                if v not in state_vars:
                                    state_vars.append(v)
                        else:
                            if var not in state_vars:
                                state_vars.append(var)
        state_vars = list(set(state_vars))
        func_names = list(set(func_names))
        all_contracts_details[contract['name']] = {
            'func': func_names, 'vars': state_vars, 'parents': parents, 'fbody': functions, 'maps': mappings}
        cont_functions[contract['name']] = all_functions
    return all_contracts_details, cont_functions
