from TLS_structs import tls_unpack

TLS_RESPONSES = {
    "WINSRV2012RS": [('Version', '771'), ('Cipher', 49192), ('Multiple Handshake Msg', True), ('KEX Curve', 23)],
    "WINSRV2019": [('Version', '771'), ('Cipher', 49200), ('Multiple Handshake Msg', True), ('KEX Curve', 24)],
    "WINSRV2016": [('Version', '771'), ('Cipher', 49200), ('Multiple Handshake Msg', True), ('KEX Curve', 29)],
    "WIN10": [('Version', '771'), ('Cipher', 49200), ('Multiple Handshake Msg', True), ('KEX Curve', 24)],
    "XRDP": [('Version', 'ProtocolVersion.TLS_1_3'), ('Cipher', 4866), ('Multiple Handshake Msg', False), ('KEX Curve', None)],
    "heralding": [('Version', '770'), ('Cipher', 53), ('Multiple Handshake Msg', False), ('KEX Curve', None)],
}

def tls_classify(data):
    if data[1][2][1] :
        return ["Windows" , 1]
    else:
        return ["OpenSSL" , 0]