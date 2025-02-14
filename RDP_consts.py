PROTOCOL_RDP = 0x0
PROTOCOL_SSL = 0x1
PROTOCOL_HYBRID = 0x2
PROTOCOL_RDSTLS = 0x4
PROTOCOL_HYBRID_EX = 0x8
PROTOCOL_DOWNGRADE = 0x3

protocols = {
    0: "PROTOCOL_RDP",
    1: "PROCOTOL_SSL",
    2: "PROTOCOL_HYBRID",
    4: "PROTOCOL_RDSTLS",
    8: "PROTOCOL_HYBRID_EX"
}

rdp_failure_codes = {
    0x1: "SSL_REQUIRED_BY_SERVER",
    0x2: "SSL_NOT_ALLOWED_BY_SERVER",
    0x3: "SSL_CERT_NOT_ON_SERVER",
    0x4: "INCONSISTENT_FLAGS",
    0x5: "HYBRID_REQUIRED_BY_SERVER",
    0x6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
}

rdp_neg_req_flags = {
    0x1: "RESTRICTED_ADMIN_MODE_REQUIRED",
    0x2: "REDIRECTED_AUTHENTICATION_MODE_REQUIRED",
    0x4: "CORRELATION_INFO_PRESENT"
}

rdp_neg_resp_flags = {
    0x1: "Extended Client Data Supported",
    0x2: "Graphics Pipeline Extension Supported",
    0x4: "Unused",
    0x8: "Restricted Admin Mode Supported",
    0x10: "Redirected Authentication Mode Supported"
}

user_data_header_type = {
    0xc001: "rdp_client_core_data",
    0xc002: "rdp_client_security_data",
    0xc003: "rdp_client_network_data",
    0xc004: "rdp_client_cluster_data",
    0xc005: "rdp_client_monitor_data",
    0xc006: "rdp_client_message_channel_data",
    0xc008: "rdp_client_monitor_ext_data",
    0xc00a: "rdp_client_multitransport_channel_data",
	0x0c01: "rdp_server_core_data",
	0x0c02: "rdp_server_security_data",
	0x0c03: "rdp_server_network_data",
	0x0c04: "rdp_server_message_channel_data",
	0x0c08: "rdp_server_multitransport_channel_data"
}

rdp_version = {
    0x00080001: "RDP 4.0",
    0x00080004: "RDP 5.0-8.1",
    0x00080005: "RDP 10.0",
    0x00080006: "RDP 10.1",
    0x00080007: "RDP 10.2",
    0x00080008: "RDP 10.3",
    0x00080009: "RDP 10.4",
    0x0008000A: "RDP 10.5",
    0x0008000B: "RDP 10.6",
    0x0008000C: "RDP 10.7",
}

color_depth = {
    0xca00: "4 bits per pixel",
    0xca01: "8 bits per pixel"
}

sas_sequence = {
    0xaa03: "RNS_UD_SAS_DEL"
}

keyboard_type = {
    1: "IBM PC/XT or compat (83 key)",
    2: "Olivetti 'ICO' (102 key)",
    3: "IBM PC/AT (84 key)",
    4: "IBM enhanced (101/102 key)",
    5: "Nokia 1050 or similar",
    6: "Nokia 9140 or similar",
    7: "Japanese keyboard"
}

postbeta2_color_depth = {
    0xca00: "4 bits per pixel",
    0xca01: "8 bits per pixel",
    0xca02: "15bit 555 RGB mask",
    0xca03: "16bit 565 RGB mask",
    0xca04: "24bit RGB mask"
}

high_color_depth = {
    0x4: "4 bits per pixel",
    0x8: "8 bits per pixel",
    0xf: "15bit 555 RGB mask",
    0x10: "16bit 565 RGB mask",
    0x18: "24bit RGB mask"
}

supported_color_depths = {
    0x1: "24bit RGB mask",
    0x2: "15bit 555 RGB mask",
    0x4: "16bit 565 RGB mask",
    0x8: "32bit RGB mask"
}

early_capabilities = {
    0x1: "Supporting Set Error Info PDU",
    0x2: "Requesting 32bit color depth",
    0x4: "Supporting Server Status Info PDU",
    0x8: "Supporting asymmetric crypto",
    0x10: "Unused",
    0x20: "Connection Type valid",
    0x40: "Supporting Monitor Layout PDU",
    0x80: "Supporting Network Characteristics Autodetect",
    0x100: "Supporting Graphics Pipeline Extension",
    0x200: "Supporting Dynamic Timezone",
    0x400: "Supporting Heartbeat PDU"
}

connection_type = {
    0x1: "Modem",
    0x2: "Low-speed broadband",
    0x3: "Sattelite",
    0x4: "High-speed broadband",
    0x5: "WAN",
    0x6: "LAN",
    0x7: "Autodetect"
}

client_security_flags = {
    0x1: "40bit keys required",
    0x2: "128bit keys required",
    0x8: "56bit keys required",
    0x10: "FIPS required"
}

client_network_channel_options = {
    0x80000000: "Unused",
    0x40000000: "Unused",
    0x20000000: "Unused",
    0x10000000: "Unused",
    0x08000000: "High MCS priority required",
    0x04000000: "Medium MCS priority required",
    0x02000000: "Low MCS priority required",
    0x00800000: "Data must be compressed on RDP compression",
    0x00400000: "Data must be compressed",
    0x00200000: "Unused",
    0x00100000: "Persistence required"
}

client_monitor_definition_flags = {
    0x1: "Primary monitor"
}

client_multitransport_flags = {
    0x1: "UDP FEC reliable",
    0x4: "UDP FEC lossy",
    0x100: "UDP tunnelling supported",
    0x200: "Dynamic UDP switch supported"
}

server_early_capability_flags = {
	0x1: "Reserved keys v1",
	0x2: "Dynamic DST supported",
	0x4: "Reserved keys v2"
}

keyboard_layout = {
    0x00000401: "Arabic (101)",
	0x00000402: "Bulgarian",
	0x00000404: "Chinese (Traditional) - US Keyboard",
	0x00000405: "Czech",
	0x00000406: "Danish",
	0x00000407: "German",
	0x00000408: "Greek",
	0x00000409: "US",
	0x0000040a: "Spanish",
	0x0000040b: "Finnish",
	0x0000040c: "French",
	0x0000040d: "Hebrew",
	0x0000040e: "Hungarian",
	0x0000040f: "Icelandic",
	0x00000410: "Italian",
	0x00000411: "Japanese",
	0x00000412: "Korean",
	0x00000413: "Dutch",
	0x00000414: "Norwegian",
	0x00000415: "Polish (Programmers)",
	0x00000416: "Portuguese (Brazilian ABNT)",
	0x00000418: "Romanian (Legacy)",
	0x00000419: "Russian",
	0x0000041a: "Croatian",
	0x0000041b: "Slovak",
	0x0000041c: "Albanian",
	0x0000041d: "Swedish",
	0x0000041e: "Thai Kedmanee",
	0x0000041f: "Turkish Q",
	0x00000420: "Urdu",
	0x00000422: "Ukrainian",
	0x00000423: "Belarusian",
	0x00000424: "Slovenian",
	0x00000425: "Estonian",
	0x00000426: "Latvian",
	0x00000427: "Lithuanian IBM",
	0x00000428: "Tajik",
	0x00000429: "Persian",
	0x0000042a: "Vietnamese",
	0x0000042b: "Armenian Eastern",
	0x0000042c: "Azeri Latin",
	0x0000042e: "Sorbian Standard",
	0x0000042f: "Macedonian (FYROM)",
	0x00000437: "Georgian",
	0x00000438: "Faeroese",
	0x00000439: "Devanagari-INSCRIPT",
	0x0000043a: "Maltese 47-Key",
	0x0000043b: "Norwegian with Sami",
	0x0000043f: "Kazakh",
	0x00000440: "Kyrgyz Cyrillic",
	0x00000442: "Turkmen",
	0x00000444: "Tatar",
	0x00000445: "Bengali",
	0x00000446: "Punjabi",
	0x00000447: "Gujarati",
	0x00000448: "Oriya",
	0x00000449: "Tamil",
	0x0000044a: "Telugu",
	0x0000044b: "Kannada",
	0x0000044c: "Malayalam",
	0x0000044d: "ASSAMESE - INSCRIPT",
	0x0000044e: "Marathi",
	0x00000450: "Mongolian Cyrillic",
	0x00000451: "Tibetan (People's Republic of China)",
	0x00000452: "United Kingdom Extended",
	0x00000453: "Khmer",
	0x00000454: "Lao",
	0x0000045a: "Syriac",
	0x0000045b: "Sinhala",
	0x00000461: "Nepali",
	0x00000463: "Pashto (Afghanistan)",
	0x00000465: "Divehi Phonetic",
	0x0000046d: "Bashkir",
	0x0000046e: "Luxembourgish",
	0x0000046f: "Greenlandic",
	0x00000480: "Uighur",
	0x00000481: "Maori",
	0x00000485: "Yakut",
	0x00000804: "Chinese (Simplified) - US Keyboard",
	0x00000807: "Swiss German",
	0x00000809: "United Kingdom",
	0x0000080a: "Latin American",
	0x0000080c: "Belgian French",
	0x00000813: "Belgian (Period)",
	0x00000816: "Portuguese",
	0x0000081a: "Serbian (Latin)",
	0x0000082c: "Azeri Cyrillic",
	0x0000083b: "Swedish with Sami",
	0x00000843: "Uzbek Cyrillic",
	0x00000850: "Mongolian (Mongolian Script)",
	0x0000085d: "Inuktitut - Latin",
	0x00000c0c: "Canadian French (Legacy)",
	0x00000c1a: "Serbian (Cyrillic)",
	0x00001009: "Canadian French",
	0x0000100c: "Swiss French",
	0x00001809: "Irish",
	0x0000201a: "Bosnian (Cyrillic)",
	0x00010401: "Arabic (102)",
	0x00010402: "Bulgarian (Latin)",
	0x00010405: "Czech (QWERTY)",
	0x00010407: "German (IBM)",
	0x00010408: "Greek (220)",
	0x00010409: "United States - Dvorak",
	0x0001040a: "Spanish Variation",
	0x0001040e: "Hungarian 101-key",
	0x00010410: "Italian (142)",
	0x00010415: "Polish (214)",
	0x00010416: "Portuguese (Brazilian ABNT2)",
	0x00010418: "Romanian (Standard)",
	0x00010419: "Russian (Typewriter)",
	0x0001041b: "Slovak (QWERTY)",
	0x0001041e: "Thai Pattachote",
	0x0001041f: "Turkish F",
	0x00010426: "Latvian (QWERTY)",
	0x00010427: "Lithuanian",
	0x0001042b: "Armenian Western",
	0x0001042e: "Sorbian Extended",
	0x0001042f: "Macedonian (FYROM) - Standard",
	0x00010437: "Georgian (QWERTY)",
	0x00010439: "Hindi Traditional",
	0x0001043a: "Maltese 48-key",
	0x0001043b: "Sami Extended Norway",
	0x00010445: "Bengali - INSCRIPT (Legacy)",
	0x0001045a: "Syriac Phonetic",
	0x0001045b: "Sinhala - wij 9",
	0x0001045d: "Inuktitut - Naqittaut",
	0x00010465: "Divehi Typewriter",
	0x0001080c: "Belgian (Comma)",
	0x0001083b: "Finnish with Sami",
	0x00011009: "Canadian Multilingual Standard",
	0x00011809: "Gaelic",
	0x00020401: "Arabic (102) AZERTY",
	0x00020402: "Bulgarian (phonetic layout)",
	0x00020405: "Czech Programmers",
	0x00020408: "Greek (319)",
	0x00020409: "United States - International",
	0x00020418: "Romanian (Programmers)",
	0x0002041e: "Thai Kedmanee (non-ShiftLock)",
	0x00020422: "Ukrainian (Enhanced)",
	0x00020427: "Lithuanian New",
	0x00020437: "Georgian (Ergonomic)",
	0x00020445: "Bengali - INSCRIPT",
	0x0002083b: "Sami Extended Finland-Sweden",
	0x00030402: "Bulgarian (phonetic layout)",
	0x00030408: "Greek (220) Latin",
	0x00030409: "United States-Devorak for left hand",
	0x0003041e: "Thai Pattachote (non-ShiftLock)",
	0x00040408: "Greek (319) Latin",
	0x00040409: "United States-Dvorak for right hand",
	0x00050409: "Greek Latin",
	0x00060408: "Greek Polytonic"
}
