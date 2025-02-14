from multiprocessing import Pool
import csv
import json
import binascii
import argparse 
import time
import os

#from classification import rdp_classif_columns, init_rdp_row, print_rdp_row
from RDP_classify import RESPONSES, classify_response, formats, formats_credssp
from TLS_structs import tls_unpack
#from meta_structs import MetaStructParseError
from TLS_classify import tls_classify, TLS_RESPONSES

p = argparse.ArgumentParser()
p.add_argument("--response_log", type=str, default="/root/rdp_scan/scans_22_11_10_11_33_36/response_dump.csv")
p.add_argument("--num-workers", type=int, default=4)
p.add_argument("--head", type=int, default=100)
args = p.parse_args()

NUM_WORKERS = args.num_workers
NUM_PACKETS = 4

class BadRDPException(Exception):
    pass

class Processor():
    def __init__(self):
        self.counts_total = 0
        self.data = dict()
        self.unknowns = set()
        self.tls_counts = {
            "No Data": 0,
            "HANDSHAKE": 0,
            "UNKN Windows": 0,
            "UNKN OpenSSL": 0,
            "Mixed": 0
        }

        self.counts = {
            "CONN": dict(),
            "UNKN": dict(),
            "ERR": dict(),
            "SSLERR": dict(),
            "CONN_INIT": dict(),
            "HTTP": dict(),
            "SSH": dict(),
            "NON-RDP ERR": dict()
        }

        for key in RESPONSES:
            self.counts[key] = dict()

        for key in TLS_RESPONSES:
            self.tls_counts[key] = 0

    def calculate_class(self, ip):
        if not self.data[ip]["tls_classes"]:
            tls_class = "No Data"
        else:
            tls_class = " / ".join(set(self.data[ip]["tls_classes"]))
        
        self.data[ip]["tls_class"] = tls_class
        try:
            self.tls_counts[tls_class] += 1
        except KeyError:
            self.tls_counts["Mixed"] += 1

        norm_fact = len(self.data[ip]["classifs_raw"])
        sums = dict()
        for key in self.counts:
            sums[key] = 0
            for el in self.data[ip]["classifs_raw"]:
                try:
                    sums[key] += el[key][0]
                except KeyError:
                    pass
        for key in self.counts:
            sums[key] /= norm_fact
        classif = max(sums, key=lambda x: sums[x])
        self.data[ip]["class"] = classif
        self.data[ip]["class_simil"] = f"{sums[classif]:.2f}"
        diff_fields = []
        for el in self.data[ip]["classifs_raw"]:
            if classif in el:
                if el[classif][1]:
                    diff_fields.append(el[classif][1])
        diff_fields = [list(x) for x in set(tuple(x) for x in diff_fields)]
        self.data[ip]["class_simil"] += f" {tls_class}"
        self.data[ip]["class_simil"] += f" {diff_fields}" if diff_fields else ""

        if not self.data[ip]["class_simil"] in self.counts[self.data[ip]["class"]]:
            self.counts[self.data[ip]["class"]][self.data[ip]["class_simil"]] = 0
        self.counts[self.data[ip]["class"]][self.data[ip]["class_simil"]] += 1
        self.counts_total += 1

        del self.data[ip]["classifs_raw"]
        del self.data[ip]["tls_classes"]

    def process_records(self, p_idx):
        with open(args.response_log) as f:
            rd = csv.reader(f)
            not_rdp = set()
            for l_idx, line in enumerate(rd):
                if args.head and l_idx > args.head:
                    return
                if line[1] == '3':#降级先不考虑
                    continue
                    ip, conn_type, rtt_data, raw_data, = line
                else:
                    ip, conn_type, rtt_data, raw_data, enc_data, json_data = line
                #ip, raw_data, enc_data, conn_type, json_data = line
                
                # skip records a other process handels
                if int(ip.split(".")[-1]) % NUM_WORKERS != p_idx:
                    continue

                add_data = json.loads(json_data)
                conn_type = int(conn_type)
                conn_exc = -1 if not "exception" in add_data else add_data["exception"]
                raw_data = binascii.unhexlify(raw_data)
                enc_data = binascii.unhexlify(enc_data)

                # initialize a new dictionary entry for the IP
                if not ip in self.data:#很重要
                    #self.data[ip] = init_rdp_row()
                    self.data[ip] = dict()
                    self.data[ip]["ip"] = ip
                    self.data[ip]["classifs_raw"] = []
                    self.data[ip]["counter"] = 0
                    self.data[ip]["tls_classes"] = []
                else:
                    if self.data[ip]["counter"] == NUM_PACKETS:
                        print(f"WARNING: One ip appears more than {NUM_PACKETS} times!")

                classifs = dict()
                try:
                    resps = []
                    data_offset = 0
                    if conn_type == 0 or conn_type == 4:
                        # Try to unpack only from unencrypted data
                        for i, fmt in enumerate(formats):
                            if not raw_data[data_offset:]:
                                resps.append({"exception": conn_exc, "data": ""})
                                break
                            # # weird xrdp data xrdp时linux中rdp server实现，tpktHeader 
                            # if raw_data[data_offset:].startswith(b"\x03\x00\x00\x09"):
                            #     unp_data, l = xrdp_err.unpack(raw_data[data_offset:])
                            #     resps.append({"exception": -1, "data": unp_data})
                            #     break
                            # # wird vbox data
                            # if raw_data[data_offset:].startswith(b"\x03\x00\x00\x0b"):
                            #     unp_data, l = vbox_err.unpack(raw_data[data_offset:])
                            #     resps.append({"exception": -1, "data": unp_data})
                            #     break
                            unp_data, l = fmt.unpack(raw_data[data_offset:])
                            data_offset += l
                            resps.append({"exception": -1, "data": unp_data})
                        else:
                            resps[-1]["exception"] = conn_exc
                    else:
                        # Try to unpack from unencrypted and decrypted data
                        if not raw_data[data_offset:]:
                            resps.append({"exception": conn_exc, "data": ""})
                        else: 
                            if not raw_data.startswith(b"\x03"):#不是03开头，不是rdp协议
                                raise BadRDPException()
                            unp_data, l = formats[0].unpack(raw_data)#formats[0]是x224
                            tls_data = raw_data[l:]#x224之后是tls协议
                            if tls_data:
                                try:
                                    tls_class, tls_recordnum = tls_classify(tls_unpack(tls_data))#这里做了tls实现的分类
                                except:
                                    tls_class = "HANDSHAKE"
                                    tls_recordnum = -1
                                self.data[ip]["tls_classes"].append(tls_class)
                            resps.append({"exception": -1, "data": unp_data})

                            for fmt in formats[1:]:#分析tls协商后的加密信息，就是MCS部分或者cred了
                                if not enc_data[data_offset:]:
                                    resps.append({"exception": conn_exc, "data": ""})
                                    break
                                # weird xrdp data 0300000902f0802180
                                # if enc_data.startswith(b"\x03\x00\x00\x09"):
                                #     unp_data, l = xrdp_err.unpack(enc_data[data_offset:])
                                #     resps.append({"exception": -1, "data": unp_data})
                                #     break
                                # credssp data
                                if not enc_data.startswith(b"\x03"):
                                    # unp_data, l = formats_credssp[1].unpack(enc_data[data_offset:])#formats_credssp[1]处理cred没有实现
                                    resps.append({"exception": -1, "data": "formats_credssp"})
                                    break
                                
                                unp_data, l = fmt.unpack(enc_data[data_offset:])
                                data_offset += l
                                resps.append({"exception": -1, "data": unp_data})
                            else:
                                resps[-1]["exception"] = conn_exc

                    # only classify as connection close if there is zero data and if there is more to expect (type != 4)
                    if (len(resps) < 2) and (not resps[0]["data"]) and (conn_type != 4):
                            classifs["CONN"] = (3.0, [])
                    else:
                        # get classifications
                        classifs.update(classify_response(resps, conn_type))
                # except (BadRDPException, MetaStructParseError) as e:
                except (BadRDPException) as e:
                    self.unknowns.add(raw_data[:32])
                    if b"HTTP" in raw_data:
                        classifs["HTTP"] = (1.0, [])
                    elif b"SSH" in raw_data:
                        classifs["SSH"] = (1.0, [])
                    elif raw_data and raw_data[0] == 0x3:
                        classifs["ERR"] = (1.0, [])
                    else:
                        classifs["NON-RDP ERR"] = (1.0, [])

                self.data[ip]["classifs_raw"].append(classifs)
                self.data[ip]["counter"] += 1
                if self.data[ip]["counter"] == NUM_PACKETS:
                    self.calculate_class(ip)

                # no classification could me made
                if not classifs:
                    classifs["UNKN"] = (1.0, [])

def do_work(p_idx):
    p = Processor()
    p.process_records(p_idx)
    return p

csv.field_size_limit(csv.field_size_limit() * 10)
cfn = os.path.join(os.path.dirname(args.response_log), "classification.csv")

with Pool(NUM_WORKERS) as p: 
    idx = list(range(NUM_WORKERS))
    res = p.map(do_work, idx)

    # Merge stuff together
    final_res = Processor()
    for r in res:
        final_res.data.update(r.data)
        final_res.unknowns |= r.unknowns
        final_res.counts_total += r.counts_total
        for i in r.tls_counts.keys():
            final_res.tls_counts[i] += r.tls_counts[i]
        for i in r.counts.keys():
            for x in r.counts[i].keys():
                if x in final_res.counts[i]:
                    final_res.counts[i][x] += r.counts[i][x]
                else:
                    final_res.counts[i][x] = r.counts[i][x]
    
    todel = []
    for ip in final_res.data:
        if final_res.data[ip]["counter"] < NUM_PACKETS:
            todel.append(ip)
        del final_res.data[ip]["counter"]
    for ip in todel:
        del final_res.data[ip]

    for key in final_res.counts:
        final_res.counts[key] = list(sorted(final_res.counts[key].items(), key=lambda x: x[1], reverse=True))

    print("Unknown responses:", len(final_res.unknowns))
    for el in final_res.unknowns:
        print(el)
    print()

    print("total classifications:", final_res.counts_total)
    print()

    print("total incomplete responses:", len(todel))
    print()

    for key in final_res.counts:
        print(key)
        for subkey, subval in final_res.counts[key]:
            print(f"\t{subval}: {subkey}")

    print()
    for key in final_res.tls_counts:
        print(f"{key}: {final_res.tls_counts[key]}")

    with open(cfn, "w") as f:
        # wr = csv.DictWriter(f, fieldnames=rdp_classif_columns)
        wr = csv.DictWriter(f)
        for values in final_res.data.values():
            wr.writerow(values)
