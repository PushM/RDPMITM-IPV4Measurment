import struct
import math

from RDP_consts import *
from meta_structs import *

tpkt_hdr = Header("TPKT Header", [
    Field("0x3", ">B", 1),
    Field("TPKT.Reserved", ">B", 1),
    Field("TPKT.Length", ">H", 2)
])

x224_cr = Header("X224 Connetion Request", [
    Field("X224.Length", ">B", 1),
    Field("CR CDT", ">B", 1),
    Field("DST_REF", ">H", 2),
    Field("SRC_REF", ">H", 2),
    Field("Class Option", ">B", 1)
])

x224_data = Header("X224 Data", [
    Field("X224.Length", ">B", 1),
    Field("DT ROA", ">B", 1),
    Field("EOT", ">B", 1)
])

rdp_neg_req = Header("RDP Negotiation Request", [
    Field("NegoReq.Type", "<B", 1),
    Field("NegoReq.Flags", "<B", 1, format_flags(rdp_neg_req_flags)),
    Field("NegoReq.Length", "<H", 2),
    Field("Requested Protocol", "<I", 4, lookup_format(protocols))
])

rdp_neg_resp = Header("RDP Negotiation Response", [
    Field("NegoResp.Type", "<B", 1),
    Field("NegoResp.Flags", "<B", 1, format_flags(rdp_neg_resp_flags)),
    Field("NegoResp.Length", "<H", 2),
    Field("Selected Protocol", "<I", 4, lookup_format(protocols))
])

rdp_neg_failure = Header("RDP Negotiation Failure", [
    Field("NegoFailure.Type", "<B", 1),
    Field("NegoFailure.Flags", "<B", 1),
    Field("NegoFailure.Length", "<H", 2),
    Field("NegoFailure.Failure Code", "<I", 4, lookup_format(rdp_failure_codes))
])

cookie = TerminatedField("Cookie", b"\r\n")

x224_conn_req = Header("X224 Connection Request", [
    tpkt_hdr,
    x224_cr,
    cookie,
    rdp_neg_req
])

x224_conn_conf = Header("X224 Connection Confirm", [
    tpkt_hdr,
    x224_cr,
    AlternativeTypeHeader(Field("Type", "<B", 1), {
        0x2 : rdp_neg_resp,
        0x3 : rdp_neg_failure
    })
])

t124_ccrq = Field("t124 CC request", "23s", 23)

rdp_client_core_data = OptionalFieldHeader("RDP Client Core Data", [
    Field("ClientData.Core.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Core.Length", "<H", 2),
    Field("ClientData.Core.Version", "<I", 4, lookup_format(rdp_version)),
    Field("Desktop Width", "<H", 2),
    Field("Desktop Height", "<H", 2),
    Field("color Depth", "<H", 2, lookup_format(color_depth)),
    Field("SASSequence", "<H", 2, lookup_format(sas_sequence)),
    Field("Keyboard Layout", "<I", 4, lookup_format(keyboard_layout)),
    Field("Client Build", "<I", 4),
    Field("Client Name", "32s", 32, deinterlace_zeroes),
    Field("Keyboard Type", "<I", 4, lookup_format(keyboard_type)),
    Field("Keyboard Subtype", "<I", 4),
    Field("Keyboard Function Key", "<I", 4),
    Field("ime File Name", "64s", 64, strip_zeroes),
    Field("postBeta2ColorDepth", "<H", 2, lookup_format(postbeta2_color_depth)),
    Field("Client Product ID", "<H", 2),
    Field("Serial Number", "<I", 4),
    Field("High Color Depth", "<H", 2, lookup_format(high_color_depth)),
    Field("Supported Color Depths", "<H", 2, format_flags(supported_color_depths)),
    Field("Early Capability Flags", "<H", 2, format_flags(early_capabilities)),
    Field("Client Dig Product ID", "64s", 64, strip_zeroes),
    Field("Connection Type", "B", 1, lookup_format(connection_type)),
    Field("Alignment Padding", "B", 1),
    Field("Server Selected Protocol", "<I", 4, lookup_format(protocols)),
    Field("Desktop Physical Width", "<I", 4),
    Field("Desktop Physical Height", "<I", 4),
    Field("Desktop Orientation", "<H", 2),
    Field("Desktop Scale Factor", "<I", 4),
    Field("Device Scale Factor", "<I", 4)
], 1)

rdp_client_security_data = Header("RDP Client Security Data", [
    Field("ClientData.Security.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Security.Length", "<H", 2),
    Field("Encryption Methods", "<I", 4, format_flags(client_security_flags)),
    Field("Ext Encryption Methods (French only 0)", "<I", 4, format_flags(client_security_flags))
])

rdp_client_network_data = RepeatedFieldHeader("RDP Client Network Data", [
    Field("ClientData.Network.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Network.Length", "<H", 2),
    Field("Channel Count", "<I", 4),
    Header("Channel Definition", [
        Field("Name", "8s", 8, strip_zeroes),
        Field("Options", "<I", 4, format_flags(client_network_channel_options))
    ])
], 2, 3)

rdp_client_cluster_data = Header("RDP Client Cluster Data", [
    Field("ClientData.Cluster.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Cluster.Length", "<H", 2),
    Field("ClientData.Cluster.Flags", "<I", 4),
    Field("Redirected Session ID", "<I", 4)
])

rdp_client_monitor_data = RepeatedFieldHeader("RDP Client Monitor Data", [
    Field("ClientData.Monitor.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Monitor.Length", "<H", 2),
    Field("ClientData.Monitor.Flags (Unused 0)", "<I", 4),
    Field("Monitor Count", "<I", 4),
    Header("Monitor Definition", [
        Field("Left", "<I", 4),
        Field("Top", "<I", 4),
        Field("Right", "<I", 4),
        Field("Bottom", "<I", 4),
        Field("Flags", "<I", 4, format_flags(client_monitor_definition_flags))
    ])
], 3, 4)

rdp_client_message_channel_data = Header("RDP Client Message Channel Data", [
    Field("ClientData.MessageChannel.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.MessageChannel.Length", "<H", 2),
    Field("ClientData.MessageChannel.Flags (Unused 0)", "<I", 4)
])

rdp_client_multitransport_channel_data = Header("RDP Client Multitransport Channel Data", [
    Field("ClientData.Multitransport.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.Multitransport.Length", "<H", 2),
    Field("ClientData.Multitransport.Flags", "<I", 4, format_flags(client_multitransport_flags))
])

rdp_client_monitor_ext_data = RepeatedFieldHeader("RDP Client Monitor Extended Data", [
    Field("ClientData.MonitorExt.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ClientData.MonitorExt.Length", "<H", 2),
    Field("ClientData.MonitorExt.Flags (unused 0)", "<I", 4),
    Field("Monitor Count", "<I", 4),
    Header("Monitor Attributes", [
        Field("Physical Width", "<I", 4),
        Field("Physical Height", "<I", 4),
        Field("Orientation", "<I", 4),
        Field("Desktop Scale Factor", "<I", 4),
        Field("Device Scale Factor", "<I", 4),
    ])
], 3, 4)

rdp_client_data = VariableOrderHeader("RDP Client Data", [
    rdp_client_core_data,
    rdp_client_security_data,
    rdp_client_network_data,
    rdp_client_cluster_data,
    rdp_client_monitor_data,
    rdp_client_message_channel_data,
    rdp_client_multitransport_channel_data,
    rdp_client_monitor_ext_data
], {
    0xc001: 0,
    0xc002: 1,
    0xc003: 2,
    0xc004: 3,
    0xc005: 4,
    0xc006: 5,
    0xc008: 7,
    0xc00a: 6
}, "<H", 0, 2, 0, 0)

t125_ci_userdata = BERField("User Data", "", 4)
t125_ci_userdata_inner = Header("User Data (inner)", [
    Field("GCC Connect Data", "21s", 21),
    Field("UeserData.Length", ">H", 2, hex),
    rdp_client_data
])

def t125_ci_userdata_format(data, depth):
    _, data = data
    print('\t' * depth, "User Data")
    t125_ci_userdata_inner.format(data[0], depth + 1)

def t125_ci_userdata_unpack(data):
    ind, datalen = t125_ci_userdata.unpack_header(data)
    t125_ci_userdata_inner.fields[2].length = datalen - 25
    return ("User Data", [t125_ci_userdata_inner.unpack(data[ind:])[0]]), ind + datalen

t125_ci_userdata.unpack = t125_ci_userdata_unpack
t125_ci_userdata.format = t125_ci_userdata_format

t125_ci = BERSequence("T.125 Connect Initial", 0x7f65, [
    BERField("Calling Domain Selector", ">B", 4),
    BERField("Called Domain Selector", ">B", 4),
    BERField("Upward Flag", ">B", 1, bool),
    BERSequence("Target Domain Parameters", 0x30, [
        BERField("Max Channel IDs", ">H", 2),
        BERField("Max User IDs", ">H", 2),
        BERField("Max Token IDs", ">H", 2),
        BERField("Num Priorities", ">H", 2),
        BERField("Min Throughput", ">H", 2),
        BERField("Max Height", ">H", 2),
        BERField("Max MCSPDU Size", ">H", 2),
        BERField("Protocol Version", ">H", 2)
    ]),
    BERSequence("Minimum Domain Parameters", 0x30, [
        BERField("Max Channel IDs", ">H", 2),
        BERField("Max User IDs", ">H", 2),
        BERField("Max Token IDs", ">H", 2),
        BERField("Num Priorities", ">H", 2),
        BERField("Min Throughput", ">H", 2),
        BERField("Max Height", ">H", 2),
        BERField("Max MCSPDU Size", ">H", 2),
        BERField("Protocol Version", ">H", 2)
    ]),
    BERSequence("Maximum Domain Parameters", 0x30, [
        BERField("Max Channel IDs", ">H", 2),
        BERField("Max User IDs", ">H", 2),
        BERField("Max Token IDs", ">H", 2),
        BERField("Num Priorities", ">H", 2),
        BERField("Min Throughput", ">H", 2),
        BERField("Max Height", ">H", 2),
        BERField("Max MCSPDU Size", ">H", 2),
        BERField("Protocol Version", ">H", 2)
    ]),
    t125_ci_userdata
])

mcs_initial = Header("Client MCS Connect Intitial", [
    tpkt_hdr,
    x224_data,
    t125_ci
])

rdp_server_core_data = OptionalFieldHeader("RDP Server Core Data", [
    Field("ServerData.Core.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ServerData.Core.Length", "<H", 2),
    Field("ServerData.Core.Version", "<I", 4, lookup_format(rdp_version)),
    Field("Client Requested Protocol", "<I", 4, lookup_format(protocols)),
    Field("Early Capability flags", "<I", 4)
], 1)

rdp_server_security_data = OptionalFieldHeader("RDP Server Security Data", [
    Field("ServerData.Security.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ServerData.Security.Length", "<H", 2),
    Field("Encryption Method", "<I", 4),
    Field("Encryption Level", "<I", 4),
    VariableLengthHeader("Encryption Info", [
        Field("Server Random Length", "<I", 4),
        Field("Server Certificate Length", "<I", 4),
        Field("Server Random", "", 0),
        Field("Server Certificate", "", 0)
    ], {
        0: 2,
        1: 4
    })
], 1)

rdp_server_network_data = RepeatedFieldHeader("RDP Server Network Data", [
    Field("ServerData.Network.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ServerData.Network.Length", "<H", 2),
    Field("MS Channel ID", "<H", 2),
    Field("Channel Count", "<H", 2),
    Field("Channel IDs", "<H", 2),
    Field("ServerData.Network.Padding", "<H", 2)
    ], 3, 4, padding_field=(5, lambda x: x[3][1] % 2 == 1))

rdp_server_channel_data = Header("RDP Server Channel Data", [
    Field("ServerData.Channel.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ServerData.Channel.Length", "<H", 2),
    Field("MS Channel ID", "<H", 2)
])

rdp_server_multitransport_data = Header("RDP Server Channel Data", [
    Field("ServerData.Multitransport.Type", "<H", 2, lookup_format(user_data_header_type)),
    Field("ServerData.Multitransport.Length", "<H", 2),
    Field("ServerData.Multitransport.Flags", "<I", 4)
])

rdp_server_data = VariableOrderHeader("RDP Server Data", [
    rdp_server_core_data,
    rdp_server_security_data,
    rdp_server_network_data,
    rdp_server_channel_data,
    rdp_server_multitransport_data
], {
    0x0c01: 0,
    0x0c02: 1,
    0x0c03: 2,
    0x0c04: 3,
    0x0c08: 4
}, "<H", 0, 2, 0, 0)

t125_cr_userdata = BERField("User Data", "", 4)
t125_cr_userdata_inner = Header("User Data (inner)", [
    Field("GCC Connect Data", "23s", 23),
    rdp_server_data
])

def t125_cr_userdata_format(data, depth):
    _, data = data
    print('\t' * depth, "User Data")
    t125_cr_userdata_inner.format(data[0], depth + 1)

def t125_cr_userdata_unpack(data):
    ind, datalen = t125_cr_userdata.unpack_header(data)
    if data[ind + 23] == 0xc:
        data_offset = 22
    else:
        data_offset = 23
    t125_cr_userdata_inner.fields[1].length = datalen - data_offset
    t125_cr_userdata_inner.fields[0].length = data_offset
    t125_cr_userdata_inner.fields[0].fmt = str(data_offset) + "s"
    return ("User Data", [t125_cr_userdata_inner.unpack(data[ind:])[0]]), ind + datalen

t125_cr_userdata.unpack = t125_cr_userdata_unpack
t125_cr_userdata.format = t125_cr_userdata_format

t125_cr = BERSequence("T.125 Connect Response", 0x7f66, [
    BERField("Result", "B", 4),
    BERField("Called Connect ID", "B", 1, bool),
    BERSequence("Domain Parameters", 0x30, [
        BERField("Max Channel IDs", ">B", 2, dynamic_fmt=True),
        BERField("Max User IDs", ">B", 2, dynamic_fmt=True),
        BERField("Max Token IDs", ">B", 2, dynamic_fmt=True),
        BERField("Num Priorities", ">B", 2, dynamic_fmt=True),
        BERField("Min Throughput", ">B", 2, dynamic_fmt=True),
        BERField("Max Height", ">B", 2, dynamic_fmt=True),
        BERField("Max MCSPDU Size", ">B", 2, dynamic_fmt=True),
        BERField("Protocol Version", ">B", 2, dynamic_fmt=True)
    ]),
    t125_cr_userdata
])

mcs_response = Header("Server MCS Connect Response", [
    tpkt_hdr,
    x224_data,
    t125_cr
])



def build_x224_conn_req(cookieval=b"Cookie: mstshash=kabi", flags=0xff, protocols=PROTOCOL_SSL):
    tpkt_len = 21 + len(cookieval)
    x224_len = 16 + len(cookieval)
    return x224_conn_req.pack([[3, 0, tpkt_len], [x224_len, 0xe0, 0, 0, 0], cookieval, [1, flags, 8, protocols]])

rdp_client_core_default = [0xc001, 216, 0x80004, 1024, 768, 0xca01, 0xaa03, 0x409, 2600, interlace_zeroes("novosibirsk", 32), 0x4, 0, 12, b'\x00' * 64, 0xca01, 1, 0, 0x18, 0xb, 0x1, b'\x00' * 64, 0, 0, 1]
rdp_client_security_default = [0xc002, 12, 0, 0]
rdp_client_network_default = [0xc003, 68, 5, [b'cliprdr\0', 0xa0c0], [b'rdpsnd\0\0', 0xc0], [b'snddbg\0\0', 0xc0], [b'rdpdr\0\0\0', 0x8080], [b'drdynvc\0', 0xc0]]
rdp_client_cluster_default = [0xc004, 12, 13, 0]

def build_mcs_initial(
    calling_domain = 1,
    called_domain = 1,
    upward_flag = 0xff,
    target_max_channel_ids = 34,
    target_max_userids = 2,
    target_max_tokenids = 0,
    target_num_prios = 1,
    target_min_througput = 0,
    target_max_height = 1,
    target_max_mcs_pdusize = 65535,
    target_protocol_version = 2,
    min_max_channel_ids = 1,
    min_max_userids = 1,
    min_max_tokenids = 1,
    min_num_prios = 1,
    min_min_througput = 0,
    min_max_height = 1,
    min_max_mcs_pdusize = 1056,
    min_protocol_version = 2,
    max_max_channel_ids = 65535,
    max_max_userids = 64535,
    max_max_tokenids = 65535,
    max_num_prios = 1,
    max_min_througput = 0,
    max_max_height = 1,
    max_max_mcs_pdusize = 65535,
    max_protocol_version = 2,
    rdp_client_core = rdp_client_core_default,
    rdp_client_security = rdp_client_security_default,
    rdp_client_network = rdp_client_network_default,
    rdp_client_cluster = rdp_client_cluster_default,
    rdp_client_monitor = None,
    rdp_client_channel = None,
    rdp_client_multitransport = None,
    rdp_client_monitor_ext = None
):
    rdp_data = rdp_client_data.pack([rdp_client_core, rdp_client_security, rdp_client_network, rdp_client_cluster, rdp_client_monitor, rdp_client_channel, rdp_client_multitransport, rdp_client_monitor_ext])
    mcs_userdata = b'\x00\x05\x00\x14|\x00\x01\x81B\x00\x08\x00\x10\x00\x01\xc0\x00Duca' + struct.pack(">H", 0x8000 + len(rdp_data)) + rdp_data
    t125_ci_data = [calling_domain, called_domain, upward_flag, 
        [target_max_channel_ids, target_max_userids, target_max_tokenids, target_num_prios, target_min_througput, target_max_height, target_max_mcs_pdusize, target_protocol_version],
        [min_max_channel_ids, min_max_userids, min_max_tokenids, min_num_prios, min_min_througput, min_max_height, min_max_mcs_pdusize, min_protocol_version],
        [max_max_channel_ids, max_max_userids, max_max_tokenids, max_num_prios, max_min_througput, max_max_height, max_max_mcs_pdusize, max_protocol_version], mcs_userdata]

    tpkt_len = 7 + len(t125_ci.pack(t125_ci_data))
    return mcs_initial.pack([[0x3, 0, tpkt_len], [2, 0xf0, 0x80], t125_ci_data])

#print(build_mcs_initial())