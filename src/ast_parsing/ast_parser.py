from solidity_parser import parser as slither_parser

def generate_ast(code):
    source_unit = slither_parser.parse(code)
    children = source_unit['children']
    compiler_version = children[0]['value']
    return children, compiler_version

def check_nodes(sub_nodes, definition, functions, variables, mappings):
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
            functions, variables, mappings = check_nodes(
                statement['body'], definition, functions, variables, mappings)
    return functions, variables, mappings


def check_mapping(statement, definition, functions, variables, mappings):
    if statement['expression']['type'] == 'BinaryOperation':
        if '=' in statement['expression']['operator'] and statement['expression']['operator'] != '==':
            if statement['expression']['left']['type'] == 'IndexAccess':
                tmp = statement['expression']['left']
                while 'base' in tmp['base']:
                    tmp = tmp['base']
                if tmp['base']['name'] in mappings:
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
    functions, variables, mappings = check_nodes(
        statements, definition, functions, variables, mappings)
    statements = statement['FalseBody']

    if statements == None:
        return
    functions, variables, mappings = check_nodes(
        statements, definition, functions, variables, mappings)
    return functions, variables, mappings


def parse_ast(children):
    all_contracts_details = {}
    variables = []
    state_vars = []

    for contract in children:
        mappings = []
        functions = []
        func_names = []
        func_var = []
        parents = []
        try:
            sub_nodes = contract['subNodes']
        except:
            sub_nodes = []
        for definition in sub_nodes:
            if definition['type'] == 'StateVariableDeclaration':
                dec_vars = definition['variables']
                state_vars = state_vars + [var['name'] for var in dec_vars]
            try:
                if definition['type'] == 'StateVariableDeclaration':
                    if definition['variables'][0]['typeName']['type'] == 'Mapping':
                        mappings.append(definition['variables'][0]['name'])
            except:
                pass
            try:
                statements = definition['body']
                if statements != []:
                    functions, variables, mappings = check_nodes(
                        statements, definition, functions, variables, mappings)
            except KeyError:
                continue
            except:
                pass      
        # replaces duplicate names of functions
        for func in functions:
            if func['name'] not in func_names:
                func_names.append(func['name'])
                statements = func['body']['statements']
        # replaces duplicate func, var pairs
        func_var = [var for var in variables if var not in func_var]
        if contract['baseContracts'] != []:
            parents = contract['baseContracts']
            for base_contract in contract['baseContracts']:
                tmp = base_contract['baseName']['namePath']
                base_statevars = all_contracts_details[tmp]['vars']
                base_funcs = all_contracts_details[tmp]['fbody']
                functions = functions + [func for func in base_funcs]
                func_names = func_names + [func['name'] for func in base_funcs]
                for var in base_statevars:
                    if type(var) == list:
                        var_list = var
                        state_vars = state_vars + [var for var in var_list]
                    else:
                        state_vars.append(var)
        state_vars = list(set(state_vars))
        func_names = list(set(func_names))
        all_contracts_details[contract['name']] = {
            'func': func_names, 'vars': state_vars, 'parents': parents, 'fbody': functions, 'maps': mappings}
    return all_contracts_details
