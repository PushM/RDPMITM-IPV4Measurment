from meta_structs import *
from TLS_consts import *

tls_shello = VariableLengthHeader("Server Hello", [
    Field("Version", ">H", 2, lookup_format(ProtocolVersion)),
    Field("Random", "", 32),
    Field("SessionID Length", ">B", 1),
    Field("SessionID", "", 0),
    Field("CipherSuite", ">H", 2, lookup_format(CipherSuite)),
    Field("Compression Method", ">B", 1),
    Field("Extensions", "", 0)
    ], {2: 3})

tls_certificate = Header("Certificate", [
    Field("Length", ">xH", 3),
    Field("Certificate", "", 0)
])

tls_sdone = Header("ServerHelloDone", [
])

# Warning this message is only valid for ECC Cipher Suites!
tls_server_key_exchange = Header("Server Key Exchange", [
    Field("Curve Type", ">B", 1, lookup_format(ECCCurveType)),
    Field("Curve", ">H", 2, lookup_format(NamedCurve))
])

#tls_handshake = NHeader("TLS Handshake Msg", [
#    Field("Type"),
#    Field("Length"),
#    AlternativeType(length="Length", 
#        types={2:tls_shello, 
#            11:tls_certificate, 
#            12:tls_skeyexchg, 
#            14:tls_sdone})
#])

tls_handshake_msg = VariableLengthHeader("TLS Handshake Msg", [
    Field("Type", ">B", 1, lookup_format(HandshakeType)),
    Field("Length", ">xH", 3), # this is a dirty hack for a field which has 3 bytes
    Field("Data", "", 0)
    ], 
    {1: 2}, 
    {0: (2, {
            2: tls_shello,
            11: tls_certificate,
            12: tls_server_key_exchange,
            14: tls_sdone
            }
        )
    }
    )

tls_handshake_proto = Many("TLS Handshake Proto", tls_handshake_msg)

tls_application_data = Header("TLS Application Data", [
])

tls_alert = Header("TLS Alert Record", [])

tls_change_cipher_spec = Header("TLS Change Cipher Spec", [
    Field("0x1", ">B", 1)
])

tls_rec = VariableLengthHeader("TLS Record", [
    Field("ContentType", ">B", 1, lookup_format(TLSContentType)),
    Field("Version", ">H", 2, lookup_format(ProtocolVersion)),
    Field("Length", ">H", 2),
    Field("Data", "", 0)
    ], {2:3}, 
    {0: (3, {
                TLSContentType.CHANGE_CIPHER_SPEC.value: tls_change_cipher_spec, 
                TLSContentType.APPLICATION_DATA.value: tls_application_data, 
                TLSContentType.HANDSHAKE.value: tls_handshake_proto,
                TLSContentType.ALERT.value: tls_alert
            }
        )
    }
)

tls_stream = Many("TLS Stream", tls_rec)

def tls_format(d, depth):
    print("\t"*depth, d[0])
    depth += 1
    try:
        print("\t"*depth, f"{d[1][0][0]}: {ProtocolVersion(d[1][0][1]).name}")
        print("\t"*depth, f"{d[1][1][0]}: {CipherSuite(d[1][1][1]).name}")
        print("\t"*depth, f"{d[1][2][0]}: {d[1][2][1]}")
    except ValueError:
        print(d)
        raise
    curve_name = None
    if d[1][3][1] is not None:
        curve_name = NamedCurve(d[1][3][1]).name
    print("\t"*depth, f"{d[1][3][0]}: {curve_name}")

def tls_unpack(data):
    """Consume all in data and treat it as a stream of TLS records.
    Returns (TLS-Version, Cipher-Suite, Multiple Handshake Msg?, ECC-Curve)"""
    parsed_len = 0
    res = []
    while parsed_len < len(data):
        ret, l = tls_rec.unpack(data[parsed_len:])
        parsed_len += l
        res.append(ret)
        if ret[1][0][1] == TLSContentType.CHANGE_CIPHER_SPEC.value:
            break

    first_record = dict(res[0][1])
    tls_version = first_record["Version"]

    max_hmsg_per_record = 0
    curve_name = None
    cipher = None
    for r in res:
        fields = dict(r[1])
        if fields["ContentType"] == TLSContentType.HANDSHAKE.value:
            messages_per_record = 0
            for m in fields["TLS Handshake Proto"]:
                messages_per_record += 1
                if m[1][2][0] == "Server Hello":
                    shello_fields = dict(m[1][2][1])
                    cipher = shello_fields["CipherSuite"]
                    if cipher & 0xff00 == 0x1300:
                        tls_version = ProtocolVersion.TLS_1_3
                if m[1][2][0] == "Server Key Exchange":
                    skex_fields = dict(m[1][2][1])
                    if skex_fields["Curve Type"] == ECCCurveType.NAMED_CURVE.value:
                        curve_name = skex_fields["Curve"]
            max_hmsg_per_record = max(max_hmsg_per_record, messages_per_record)

    return ("TLS Data", [("Version", str(tls_version)), ("Cipher", cipher), ("Multiple Handshake Msg", max_hmsg_per_record > 1), ("KEX Curve", curve_name)])
    # return ("TLS Data", [("Version", str(tls_version)), ("Cipher", cipher), ("Multiple Handshake Msg", max_hmsg_per_record), ("KEX Curve", curve_name)])
