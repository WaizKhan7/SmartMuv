import copy
from slither.slither import Slither
from configparser import ConfigParser
from src.ast_parsing.ast_parser import generate_ast
from src.ast_parsing.ast_parser import parse_ast

def generate_sol_file(cname, source_code, input_dir):
    path = input_dir + cname + ".sol"
    f = open(path, 'w')
    f.write(source_code)
    f.close()
    return path

def generate_cfgs(code_file):
    slither = Slither(code_file)
    cfgs = {}
    for cont in slither.contracts:
        cfgs[cont.name] = {}
        funcs = cont.functions
        for func in funcs:
            cfgs[cont.name][func.name] = func.nodes
    return cfgs

def expr_helper(stmt):
    if stmt['type'] == 'Identifier':
        return stmt['name']
    elif stmt['type'] == 'MemberAccess':
        return expr_helper(stmt['expression']) + ':m:' + stmt['memberName']
    elif stmt['type'] == 'IndexAccess':
        return expr_helper(stmt['base']) + ':i:' + expr_helper(stmt['index'])
    elif stmt['type'] == 'TupleExpression':
        tmp = []
        for i in stmt['components']:
            tmp.append(expr_helper(i))
        return tmp
    elif stmt['type'] == 'NumberLiteral':
        return stmt['number']


def handle_func_nodes(in_nodes, node, compiler_version):
    in_nodes_new = copy.deepcopy(in_nodes)
    tmp = str(node).split()
    keywrd = tmp[0]
    exp = str(node.expression)

    if keywrd == 'NEW':
        var = exp.split(' = ')[0]
        in_nodes_new.append([var, int(node.node_id)])
        return in_nodes_new

    elif keywrd == 'EXPRESSION':
        var = exp.split(' = ')[0]  # get left hand operand
        var = var.split('.')[0]  # get classname if member is being accessed
        if var[:8] == 'require(':
            return in_nodes_new
        code = 'pragma solidity ' + compiler_version + \
            ';\ncontract test3 {   \n    function test () public {\n       ' + \
            exp + ';\n    }    \n}'
        children, _ = generate_ast(code)
        contract = children[1]
        statements = contract['subNodes'][0]['body']['statements'][0]
        vars_used = []
        stmt = statements
        if stmt['expression']['type'] == 'BinaryOperation': 
            stmt = stmt['expression']['left']
            while 'left' in stmt:
                var_expr = expr_helper(stmt)
                if type(var_expr) == str:
                    vars_used.append(var_expr)
                elif type(var_expr) == list:
                    break
                stmt = stmt['left']
            var_expr = expr_helper(stmt)
            if type(var_expr) == str:
                if ':i:' in var_expr and not [int(node.node_id), var_expr] in reach_analysis.markednodes:
                    # to seperate indexes and base variable
                    sepv = var_expr.split(':')
                    if sepv[0] in reach_analysis.maps:
                        reach_analysis.markednodes.append(
                            [int(node.node_id), var_expr])
                vars_used.append(var_expr)
            elif type(var_expr) == list:
                for vexp in var_expr:
                    vars_used.append(vexp)
        else:
            return in_nodes_new
        # updated the old definition with new one
        for var in vars_used:
            for dff in in_nodes_new:
                if dff[0] == var:
                    ind = in_nodes_new.index(dff)
                    break
        try:
            in_nodes_new.pop(ind)
        except:
            pass
        in_nodes_new.append([var, int(node.node_id)])
        return in_nodes_new
    else:
        return in_nodes_new

def generate_final_results(results):
    final_results = {}
    for rslt in results:
        cont_name = rslt[1]
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

def reach_analysis(nodes, state_vars, fbody, mappings, compiler_version):
    out_nodes = {}
    try:
        out_nodes[nodes[0].node_id] = []
    except:
        pass
    for st_var in state_vars:
        out_nodes[nodes[0].node_id].append([st_var, 0])
    paramlist = fbody['parameters']['parameters']
    for para in paramlist:
        out_nodes[nodes[0].node_id].append([para['name'], -1])
    paramlist = ['msg.sender', 'msg.value']
    for para in paramlist:
        out_nodes[nodes[0].node_id].append([para, -1])
    for ind in range(1, len(nodes)):
        out_nodes[nodes[ind].node_id] = []

    in_nodes = {}
    UnchangesNodes = nodes
    UnchangesNodes.pop(0)
    reach_analysis.markednodes = []
    reach_analysis.maps = mappings[:]

    while not len(UnchangesNodes) == 0:
        node = UnchangesNodes.pop(0)
        preds = node._fathers
        tmp = []

        for pre in preds:
            tmp = tmp + out_nodes[pre.node_id]
        new_k = []
        for elem in tmp:
            if elem not in new_k:
                new_k.append(elem)
        in_nodes[node.node_id] = copy.deepcopy(new_k)
        out_old = copy.deepcopy(in_nodes[node.node_id])
        out_nodes[node.node_id] = copy.deepcopy(handle_func_nodes(in_nodes[node.node_id], node, compiler_version))
        
        if not out_nodes[node.node_id] == out_old:
            sucs = node._sons
            for suc in sucs:
                UnchangesNodes.append(suc)
    return in_nodes, reach_analysis.markednodes


def back_track(f_name, marked, in_nodes, finals2, func_nodes, compiler_version):
    for node in marked:
        node_details = node[1].split(':i:')
        node_name = node_details.pop(0)
        for ind in range(0, len(node_details)):
            node_details[ind] = node_details[ind].replace('msg:m:sender', 'msg.sender')
            defs = in_nodes[node[0]]
            for deff in defs:
                if deff[0] == node_details[ind]:
                    node_details[ind] = deff
        nodes = node_details[:]  # nodes is number of indexs a mapping is using
        finals = []
        # for backtracking
        for nod in nodes:
            nod_id = nod[1]
            countt = 0
            while nod_id != 0 and nod_id != -1 and nod_id != 'x' and countt < 100:
                desrd_node = [
                    f_node for f_node in func_nodes if f_node.node_id == nod_id]
                desrd_node = desrd_node[0]
                node_details = str(desrd_node).split()
                keywrd = node_details[0]
                exp = str(desrd_node.expression)
                countt += 1

                code = "pragma solidity " + compiler_version + \
                    ";\ncontract test3 {   \n    function test () public {\n       " + \
                    exp + ";\n    }    \n}"
                children, _ = generate_ast(code)
                contract = children[1]
                # there is only one statement # No need to use recursion
                statements = contract['subNodes'][0]['body']['statements'][0]
                stmt = statements
                stmt = stmt['expression']['right']

                while 'right' in stmt:
                    var_expr = expr_helper(stmt)
                    stmt = stmt['right']
                if stmt['type'] == 'NumberLiteral':
                    break
                var_expr = expr_helper(stmt)
                var_expr = var_expr.replace('msg:m:sender', 'msg.sender')
                defs = in_nodes[str(nod_id)]

                for deff in defs:
                    if deff[0] == var_expr:
                        nod_id = deff[1]
                        nod[0] = var_expr
                        break
            ind = -1
            if nod_id == -1:
                keywrd = 'Argument'
                defs = in_nodes[1]
                for deff in defs:
                    if deff[1] == -1:
                        ind = ind + 1
                    else:
                        continue
                    if deff[0] == nod[0]:
                        break

            elif nod_id == 0:
                keywrd = 'Global'
            elif nod_id == 'x':
                keywrd = 'Static'
                nod_id = nod
            finals.append(node_name)
            finals.append(nod[0])
            finals.append(nod_id)
            finals.append(keywrd)
            finals.append(ind)
        finals2.append([f_name] + finals)
    return finals2


def key_approx_analyzer(contract_name, source_code):
    config = ConfigParser()
    config.read("config.ini")
    input_dir = config.get('directories', 'contract_directory')
    children, compiler_version = generate_ast(source_code)
    children.pop(0)
    all_contracts_details = parse_ast(children)
    code_file = generate_sol_file(contract_name, source_code, input_dir)
    cfgs = generate_cfgs(code_file)    
    results = []
    # extracting all function andperforming reach analysis and back tracking on each function node
    for cntrct in all_contracts_details:
        func_names = all_contracts_details[cntrct]['func']
        functions = all_contracts_details[cntrct]['fbody']
        contract_results = []
        for f_name in func_names:
            func_nodes = cfgs[cntrct][f_name]
            for func in functions:
                if func['name'] == f_name:
                    func_body = func
                    break
            if func_body == None:
                raise ValueError

            in_nodes, marked = reach_analysis(
                func_nodes, all_contracts_details[cntrct]['vars'], func_body, all_contracts_details[cntrct]['maps'], compiler_version)
            contract_results = back_track(f_name, marked, in_nodes, contract_results, func_nodes, compiler_version)
        try:
            for result in contract_results:
                results.append([contract_name, cntrct] + result)
        except:
            results.append([contract_name, cntrct])

    final_results  = generate_final_results(results)
    return final_results
