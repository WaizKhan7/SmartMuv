
def get_bytes(_type):
    '''Takes in a type name, returns the bytes for the type'''
    # Can be optimized with static allocation of sizemap
    sizemap = {'uint': 32, 'uint256': 32, 'address': 20, 'int256': 32,
               'int': 32, 'string32': 32, 'bool': 1, 'string': 32, 'bytes': 32}
    for i in range(1, 33):
        sizemap['bytes'+str(i)] = i
    for i in range(1, 33):
        sizemap['uint'+str(i*8)] = i
    for i in range(1, 33):
        sizemap['int'+str(i*8)] = i
    return sizemap[_type]


def calculate_slots(var_arr, curr_slot_num, all_contracts):
    '''Takes in a array of variables, start slot number and list of all contracts inside the source file, returns slot number of each variable in the input array'''
    bytes_counter = []
    vars_details = []
    tmp_var_list = []
    for var in var_arr:
        if var['type'] == 'ElementaryTypeName':
            bytes = get_bytes(var['dataType'])
            var['bytes'] = bytes
            if sum(bytes_counter) + bytes > 32:
                if tmp_var_list != []:
                    curr_slot_num += 1
                    for varr in tmp_var_list:
                        varr['slot'] = curr_slot_num
                        vars_details.append(varr)
                    tmp_var_list = []
                    bytes_counter = []
                if bytes == 32:
                    curr_slot_num += 1
                    var['slot'] = curr_slot_num
                    vars_details.append(var)
                else:
                    bytes_counter.append(bytes)
                    tmp_var_list.append(var)
            elif sum(bytes_counter)+bytes == 32:
                bytes_counter.append(bytes)
                tmp_var_list.append(var)
                curr_slot_num += 1
                for varr in tmp_var_list:
                    varr['slot'] = curr_slot_num
                    vars_details.append(varr)
                tmp_var_list = []
                bytes_counter = []
            elif bytes < 32:
                bytes_counter.append(bytes)
                tmp_var_list.append(var)

        elif var['type'] == 'Mapping':
            if(tmp_var_list != []):
                curr_slot_num += 1
                for varr in tmp_var_list:
                    varr['slot'] = curr_slot_num
                    vars_details.append(varr)
                tmp_var_list = []
                bytes_counter = []

            curr_slot_num += 1
            var['slot'] = curr_slot_num
            vars_details.append(var)

        elif var['type'] == 'UserDefinedTypeName':
            if type(var['typeVars']) == str:
                curr_slot_num, tmp_lst = calculate_slots(
                    all_contracts[var['typeVars']]['vars'], curr_slot_num, all_contracts)
            else:
                curr_slot_num, tmp_lst = calculate_slots(
                    var['typeVars'], curr_slot_num, all_contracts)
            for varr in tmp_lst:
                var_dict = {}
                var_dict['type'] = varr['type']
                var_dict['name'] = var['name']+'.'+varr['name']
                var_dict['bytes'] = varr['bytes']
                var_dict['dataType'] = varr['dataType']
                var_dict['slot'] = varr['slot']
                vars_details.append(var_dict)
        elif var['type'] == 'ArrayTypeName':
            if tmp_var_list != []:
                curr_slot_num += 1
                for varr in tmp_var_list:
                    varr['slot'] = curr_slot_num
                    vars_details.append(varr)
                tmp_var_list = []
                bytes_counter = []
            if var['StorageType'] == 'dynamic':
                curr_slot_num += 1
                var['slot'] = curr_slot_num
                vars_details.append(var)
            else:
                if var['curr'] < len(var['length']) - 1:
                    tmp1 = []
                    var['curr'] += 1
                    lens = var['length']
                    lenn = len(lens)
                    var_dict = var.copy()
                    for varr in range(0, int(lens[lenn-var['curr']-1]['number'])):
                        var_dict = var.copy()
                        var_dict['name'] = var['name'] + ':' + str(varr)
                        tmp1.append(var_dict)

                    curr_slot_num, tmp_lst = calculate_slots(
                        tmp1, curr_slot_num, all_contracts)
                    for varr in tmp_lst:
                        vars_details.append(varr)
                else:
                    tmp1 = []
                    name = var['dataTypeName']
                    ty = var['dataTypeType']
                    lens = var['length']
                    var_dict = {}
                    var_dict['type'] = ty
                    var_dict['dataType'] = name
                    var_dict['name'] = var['name']
                    if(ty == 'UserDefinedTypeName'):
                        var_dict['typeVars'] = all_contracts[name]['vars']
                    tmp1.append(var_dict)
                    curr_slot_num, tmp_lst = calculate_slots(
                        tmp1, curr_slot_num, all_contracts)
                    for varr in tmp_lst:
                        vars_details.append(varr)
    if tmp_var_list != []:
        curr_slot_num += 1
        for varr in tmp_var_list:
            varr['slot'] = curr_slot_num
            vars_details.append(varr)
    return curr_slot_num, vars_details
