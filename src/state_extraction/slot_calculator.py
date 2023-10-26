
def get_bytes(_type):
    """Takes in a type name, returns the bytes for the type"""
    # Can be optimized with static allocation of sizemap
    sizemap = {'uint': 32, 'uint256': 32, 'address': 20, 'int256': 32,
               'int': 32, 'string32': 32, 'bool': 1, 'string': 32, 'bytes': 32, 'enum': 1}
    for i in range(1, 33):
        sizemap['bytes'+ str(i)] = i
    for i in range(1, 33):
        sizemap['uint'+ str(i*8)] = i
    for i in range(1, 33):
        sizemap['int'+ str(i*8)] = i
    return sizemap[_type]


def calculate_slots(var_list, curr_slot_num, all_contracts):
    """Takes in a list of variables, start slot number and list of all contracts inside the source file, returns slot number of each variable in the input list of variables"""
    current_slot_bytes = []
    current_slot_vars = []
    vars_slot_details = []
    for current_var in var_list:
        #print("current var (slot calc) ->", current_var)
        if current_var['type'] == 'ElementaryTypeName':
            current_var_bytes = get_bytes(current_var['dataType'])
            current_var['bytes'] = current_var_bytes
            if sum(current_slot_bytes) + current_var_bytes > 32:
                if current_slot_vars != []:
                    curr_slot_num += 1
                    for varr in current_slot_vars:
                        varr['slot'] = curr_slot_num
                        vars_slot_details.append(varr)
                    current_slot_vars = []
                    current_slot_bytes = []
                if current_var_bytes == 32:
                    curr_slot_num += 1
                    current_var['slot'] = curr_slot_num
                    vars_slot_details.append(current_var)
                else:
                    current_slot_bytes.append(current_var_bytes)
                    current_slot_vars.append(current_var)
            elif sum(current_slot_bytes)+current_var_bytes == 32:
                current_slot_bytes.append(current_var_bytes)
                current_slot_vars.append(current_var)
                curr_slot_num += 1
                for varr in current_slot_vars:
                    varr['slot'] = curr_slot_num
                    vars_slot_details.append(varr)
                current_slot_vars = []
                current_slot_bytes = []
            elif sum(current_slot_bytes)+current_var_bytes < 32:
                current_slot_bytes.append(current_var_bytes)
                current_slot_vars.append(current_var)

        elif current_var['type'] == 'Mapping':
            if current_slot_vars != []:
                curr_slot_num += 1
                for varr in current_slot_vars:
                    varr['slot'] = curr_slot_num
                    vars_slot_details.append(varr)
                current_slot_vars = []
                current_slot_bytes = []
            curr_slot_num += 1
            current_var['slot'] = curr_slot_num
            vars_slot_details.append(current_var)

        elif current_var['type'] == 'UserDefinedTypeName':
            # if definition type is a struct
            not_a_contract = False
            if current_var['dataType'] in all_contracts.keys():
                if 'type' not in all_contracts[current_var['dataType']].keys():
                    not_a_contract = True
                else:
                    if all_contracts[current_var['dataType']]['type'] != "ContractDefinition":
                        not_a_contract = True
            else:
                not_a_contract = True
            if not_a_contract:
                if current_slot_vars != []:
                    curr_slot_num += 1
                    for varr in current_slot_vars:
                        varr['slot'] = curr_slot_num
                        vars_slot_details.append(varr)
                current_slot_vars = []
                current_slot_bytes = []    
                tmp_lst = []
                if type(current_var['typeVars']) == str:
                    curr_slot_num, tmp_lst = calculate_slots(
                        all_contracts[current_var['typeVars']]['vars'], curr_slot_num, all_contracts)
                elif current_var['typeVars'] != []:
                    curr_slot_num, tmp_lst = calculate_slots(
                        current_var['typeVars'], curr_slot_num, all_contracts)
                elif current_var['typeVars'] == []: # if struct definition assign empty slot
                    curr_slot_num +=1
                    current_var['slot'] = curr_slot_num
                    current_var['bytes'] = 32 # not sure needs to be confirmed
                    vars_slot_details.append(current_var)
                for varr in tmp_lst:
                    var_dict = {}
                    for key in varr:
                        var_dict[key] = varr[key]
                        if key == 'name':
                            var_dict['name'] = current_var['name']+'.'+varr['name']
                    var_dict['type'] = varr['type']
                    # var_dict['name'] = var['name']+'.'+varr['name']
                    if varr['type'] != "Mapping":
                        var_dict['bytes'] = varr['bytes']
                        var_dict['dataType'] = varr['dataType']
                    var_dict['slot'] = varr['slot']
                    vars_slot_details.append(var_dict)
            else: # if its a contract definition, then it just a pointer/address and will not need a new slot like struct
                current_var['dataType'] = 'address'
                if ":key:" not in current_var['name']:
                    current_var['name'] = current_var['name']+'.address'
                current_var['type'] = 'ElementaryTypeName'
                current_var['bytes'] = 20 # as size of address is 20 bytes
                current_var_bytes = current_var['bytes']
                if sum(current_slot_bytes) + current_var_bytes > 32:
                    if current_slot_vars != []:
                        curr_slot_num += 1
                        for varr in current_slot_vars:
                            varr['slot'] = curr_slot_num
                            vars_slot_details.append(varr)
                        current_slot_vars = []
                        current_slot_bytes = []
                    if current_var_bytes == 32:
                        curr_slot_num += 1
                        current_var['slot'] = curr_slot_num
                        vars_slot_details.append(current_var)
                    else:
                        current_slot_bytes.append(current_var_bytes)
                        current_slot_vars.append(current_var)
                elif sum(current_slot_bytes)+current_var_bytes == 32:
                    current_slot_bytes.append(current_var_bytes)
                    current_slot_vars.append(current_var)
                    curr_slot_num += 1
                    for varr in current_slot_vars:
                        varr['slot'] = curr_slot_num
                        vars_slot_details.append(varr)
                    current_slot_vars = []
                    current_slot_bytes = []
                elif sum(current_slot_bytes)+current_var_bytes < 32:
                    current_slot_bytes.append(current_var_bytes)
                    current_slot_vars.append(current_var)
        elif current_var['type'] == 'ArrayTypeName':
            if current_slot_vars != []:
                curr_slot_num += 1
                for varr in current_slot_vars:
                    varr['slot'] = curr_slot_num
                    vars_slot_details.append(varr)
                current_slot_vars = []
                current_slot_bytes = []
            if current_var['StorageType'] == 'dynamic':
                curr_slot_num += 1
                current_var['slot'] = curr_slot_num
                current_var['bytes'] = get_bytes(current_var['dataTypeName'])
                current_var['dataType'] = current_var['dataTypeName']
                vars_slot_details.append(current_var)
            else: # if static array
                current_var['curr'] += 1
                if current_var['curr'] < len(current_var['length']) - 1: # in case of multi dimension array
                    lens = current_var['length']
                    lenn = len(lens)
                    tmp1 = []
                    array_len = int(lens[lenn-current_var['curr']-1])
                    var_dict = current_var.copy()
                    # current_var['curr'] += 1
                    for varr in range(0, array_len):
                        var_dict = current_var.copy()
                        var_dict['name'] = current_var['name'] + ':' + str(varr)
                        tmp1.append(var_dict)
                    curr_slot_num, tmp_lst = calculate_slots(
                        tmp1, curr_slot_num, all_contracts)
                    for varr in tmp_lst:
                        vars_slot_details.append(varr)
                else:
                    lens = current_var['length']
                    lenn = len(lens)
                    tmp1 = []
                    array_len = int(lens[lenn-current_var['curr']-1])
                    for i in range(0, array_len):
                        var_dict = {}
                        var_dict['dataType'] = current_var['dataTypeName']
                        var_dict['type'] = current_var['dataTypeType']
                        var_dict['name'] = current_var['name']+":"+str(i)
                        if var_dict['type'] == 'UserDefinedTypeName':
                            # if user defined is an enum
                            if "." in var_dict['dataType']:
                                var_dict['dataType'] = var_dict['dataType'].split(".")[-1]
                            if all_contracts[var_dict['dataType']]['vars'][0]['dataType'] == 'enum':
                                var_dict['type'] = 'ElementaryTypeName'
                                var_dict['dataType'] = 'enum'
                            else:
                                var_dict['typeVars'] = all_contracts[var_dict['dataType']]['vars']
                        tmp1.append(var_dict)
                    curr_slot_num, tmp_lst = calculate_slots(
                        tmp1, curr_slot_num, all_contracts)
                    for varr in tmp_lst:
                        vars_slot_details.append(varr)
    if current_slot_vars != []:
        curr_slot_num += 1
        for varr in current_slot_vars:
            varr['slot'] = curr_slot_num
            vars_slot_details.append(varr)
    return curr_slot_num, vars_slot_details