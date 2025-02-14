from multiprocessing import Pool
import csv
import json
import binascii
import argparse 
import time
import os, traceback, struct

#from classification import rdp_classif_columns, init_rdp_row, print_rdp_row
from RDP_classify import RESPONSES, classify_response, formats, formats_credssp
from TLS_structs import tls_unpack
#from meta_structs import MetaStructParseError
from TLS_classify import tls_classify, TLS_RESPONSES

p = argparse.ArgumentParser()
p.add_argument("--response_log", type=str, default="test.csv")
p.add_argument("--num-workers", type=int, default=1)
p.add_argument("--head", type=int, default=None)
args = p.parse_args()

NUM_WORKERS = args.num_workers
NUM_PACKETS = 10

class BadRDPException(Exception):
    pass

class Processor():
    def __init__(self):
        self.counts_total = 0
        self.data = dict()

    def process_records(self, p_idx):
        with open(args.response_log) as f:
            rd = csv.reader(f)
            for l_idx, line in enumerate(rd):
                if args.head and l_idx > args.head:
                    return
                #raw_data = None
                if line[1] == '3':#降级和nativeRDP先不考虑
                    ip, conn_type, rtt_data, = line
                    #rtt_data['connection'] = abs (rtt_data['connection'] )  
                else:
                    ip, conn_type, rtt_data, raw_data, enc_data, json_data = line
                    #rtt_data['connection'] = abs (rtt_data['connection'] )         
                    raw_data = binascii.unhexlify(raw_data)         
                # skip records a other process handels
                if int(ip.split(".")[-1]) % NUM_WORKERS != p_idx:
                    continue

                conn_type = int(conn_type)
                rtt_data = json.loads(rtt_data)
                
                #enc_data = binascii.unhexlify(enc_data)
             
                # initialize a new dictionary entry for the IP
                if not ip in self.data:#很重要
                    #self.data[ip] = init_rdp_row()
                    self.data[ip] = dict()
                    self.data[ip]["ip"] = ip
                    self.data[ip]["min_connect_rtt"] = 1000                
                    self.data[ip]["min_x224_rtt"] = 1000
                    self.data[ip]["tls"] = None
                    self.data[ip]["is_rdp"] = True
                    self.data[ip]["counter"] = 0
                else:
                    if self.data[ip]["counter"] == NUM_PACKETS:
                        print(f"WARNING: One ip:{ip} appears more than {NUM_PACKETS} times!")
               
                data_offset = 0
                if conn_type == 3:
                    # Try to unpack only from unencrypted data                        
                    # if not raw_data[data_offset:]:
                    #     continue
                    # if not self.data[ip]["is_rdp"]:#不是rdp协议
                    #     continue
                        # raise BadRDPException()
                    if rtt_data["connection"] != None and rtt_data["x224"] != None :
                        if rtt_data["connection"] < self.data[ip]["min_connect_rtt"]:
                            self.data[ip]["min_connect_rtt"] = rtt_data["connection"] 
                        if rtt_data["x224"] < self.data[ip]["min_x224_rtt"]:
                            self.data[ip]["min_x224_rtt"] = rtt_data["x224"] 
                    else:
                        continue
                    # # weird xrdp data 
                    # # wird vbox data
                else:
                    # Try to unpack from unencrypted and decrypted data
                    if not raw_data[data_offset:]:
                        self.data[ip]["is_rdp"] == False
                        continue
                    else: 
                        if not raw_data.startswith(b"\x03"):#不是03开头，不是rdp协议
                            self.data[ip]["is_rdp"] == False
                            continue 
                        try:
                            self.data[ip]["is_rdp"] == True
                            unp_data, l = formats[0].unpack(raw_data)#formats[0]是x224
                        except struct.error as e:
                            #print(ip + ":  " + str(conn_type))
                            #print("struct.error")
                            continue
                            
                        tls_data = raw_data[l:]#x224之后是tls协议
                        if tls_data:
                            try:
                                tls_class, tls_recordnum = tls_classify(tls_unpack(tls_data))#这里做了tls实现的分类
                            except:
                                #traceback.print_exc()
                                continue 
                            self.data[ip]["tls"] = tls_recordnum

                        if rtt_data["connection"] != None and rtt_data["x224"] != None :
                            if rtt_data["connection"] < self.data[ip]["min_connect_rtt"]:
                                self.data[ip]["min_connect_rtt"] = rtt_data["connection"] 
                            if rtt_data["x224"] < self.data[ip]["min_x224_rtt"]:
                                self.data[ip]["min_x224_rtt"] = rtt_data["x224"] 
                
                self.data[ip]["counter"] += 1
                # if self.data[ip]["counter"] == NUM_PACKETS:
                #     #存self.data[ip]数据到csv
                #     with open('/root/rdp_scan/scans_22_11_10_11_33_36/rdp_data.csv', "w") as f:
                #         # wr = csv.DictWriter(f, fieldnames=rdp_classif_columns)
                #         del self.data[ip]["counter"]
                #         wr = csv.DictWriter(f, fieldnames=self.data[ip].keys())
                    
                #         wr.writerow(self.data[ip])                    
                    

def do_work(p_idx):
    p = Processor()
    p.process_records(p_idx)
    return p

def main():
    csv.field_size_limit(csv.field_size_limit() * 10)

    with Pool(NUM_WORKERS) as p: 
        idx = list(range(NUM_WORKERS))
        res = p.map(do_work, idx)

        # Merge stuff together
        final_res = Processor()
        count = 0
        for r in res:
            final_res.data.update(r.data)
        todel = []
        for ip in final_res.data:
            count += 1
            if final_res.data[ip]["counter"] == 0 or final_res.data[ip]["is_rdp"] == False:
                todel.append(ip)
            del final_res.data[ip]["counter"]
            del final_res.data[ip]["is_rdp"]
        print("totoal ip:{}".format(count))
        for ip in todel:#del 发送任何等级的消息，都没有回复的,以及不是rdp，其实counter==0时is_rdp也是False
            del final_res.data[ip]

        # with open('process_data.csv', "w") as f:
        #     # wr = csv.DictWriter(f, fieldnames=rdp_classif_columns)
        #     writer = csv.DictWriter(f, fieldnames= ['ip','min_connect_rtt','min_x224_rtt','tls'],lineterminator='\n')
        #     for values in final_res.data.values():
        #         writer.writerow(values)
 
if __name__ == '__main__':
    main()