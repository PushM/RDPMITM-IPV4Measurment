from RDP_structs import *
import binascii

class RDPDiff:
    pass

formats = [
    x224_conn_conf,
    mcs_response
]

formats_credssp = [
    x224_conn_conf,
   # credssp_response
]

field_blacklist = [
    "GCC Connect Data",
    "Server Certificate",
    "Server Random",
    "TPKT.Length",
    "ServerData.Security.Length",
    "Server Certificate Length",
    "NegoResp.Flags",
    "CredSSP Payload",
    "CredSSP Version",
    "ServerData.Core.Version"
]

def isl(el):
    return isinstance(el, list) or isinstance(el, tuple)

def compare_responses(resp1, resp2, specifics):
    name1, data1 = resp1
    name2, data2 = resp2
    if name1 != name2:
        return (1, [name1 + " vs " + name2])

    if specifics:
        for key in specifics:
            if name1 == key:
                ops = specifics[key]
                if ops[0] == "&":
                    if data1 & ops[1] == ops[2]:
                        return (0, [])
                    else:
                        return (1, [name1])
                if ops[0] == "=":
                    if data1 == ops[2]:
                        return (0, [])
                    else:
                        return (1, [name1])
                if ops[0] == "range":
                    if data1 in range(ops[1], ops[2]):
                        return (0, [])
                    else:
                        return (1, [name1])

    if name1 in field_blacklist:
        return (0, [])

    diff_field_cnt = 0
    diff_fields = []
    if isl(data1) and isl(data2):
        dfc = abs(len(data1) - len(data2))
        diff_field_cnt += dfc
        if dfc > 0:
            diff_fields += ["Miss"] * dfc
        for el1, el2 in zip(data1, data2):
            dfc, dff = compare_responses(el1, el2, specifics)
            diff_field_cnt += dfc
            diff_fields += dff
        return diff_field_cnt, diff_fields
    elif (not isl(data1)) and (not isl(data2)):
        return (0, []) if data1 == data2 else (1, [name1])
    else:
        return (1, [name1 + "(type diff)"])

def compare_response_data(resps, resps_ref, specifics):
    if len(resps) != len(resps_ref):
        return 0, []
    
    diff_field_cnt = 0
    diff_fields = []
    data_offset = 0
    for i, (resp, resp_ref) in enumerate(zip(resps, resps_ref)):
        if resp["exception"] != resp_ref["exception"]:
            if resp["exception"] == 5:
                diff_field_cnt += 1
                diff_fields.append("SSL Exception")
            elif resp_ref["exception"] == -1 or resp["exception"] == -1:
                return 0, []
        else:
            if resp["exception"] == -1:
                dfc, dff = compare_responses(
                    resp["data"],
                    resp_ref["data"],
                    specifics
                )
                diff_field_cnt += dfc
                diff_fields += dff
            else:
                pass
    return (1 / (1 + diff_field_cnt)), diff_fields