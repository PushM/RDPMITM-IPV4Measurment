from multiprocessing import Pool
import csv
import json
import binascii
import argparse 
import datetime
import os, traceback, struct

#from classification import rdp_classif_columns, init_rdp_row, print_rdp_row
from RDP_classify import RESPONSES, classify_response, formats, formats_credssp
from TLS_structs import tls_unpack
#from meta_structs import MetaStructParseError
from TLS_classify import tls_classify, TLS_RESPONSES

p = argparse.ArgumentParser()
# p.add_argument("--response_log", type=str, default="D:\\大论文写作\\test.csv")

p.add_argument("--response_log", type=str, default="D:\\rdpData\\test20250213.csv")

p.add_argument("--num-workers", type=int, default=12)
p.add_argument("--head", type=int, default=None)
args = p.parse_args()

NUM_WORKERS = args.num_workers
NUM_PACKETS = 10

NOT_RESPONSE = 'NOT_RESPONSE'
NOT_START_WITH_03 = 'NOT_START_WITH_03'
NOT_RDP_SERVER_XRDP = 'NOT_RDP_SERVER_XRDP'
NOT_RDP_SERVER_VBOX = 'NOT_RDP_SERVER_VBOX'




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
                    ip, conn_type, rtt_data = line
                else:
                    ip, conn_type, rtt_data, raw_data, enc_data, json_data = line
                    #rtt_data['connection'] = abs (rtt_data['connection'] )         
                    raw_data = binascii.unhexlify(raw_data)        
                
                """
                ip, conn_type, rtt_data, raw_data, enc_data, json_data = line
                    #rtt_data['connection'] = abs (rtt_data['connection'] )         
                raw_data = binascii.unhexlify(raw_data)   
                """
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
                    self.data[ip]["x224_response"] = None
                    self.data[ip]["why_not_is_rdp"] = None
                    self.data[ip]["why_tls_is_none"] = None
                else:
                    if self.data[ip]["counter"] == NUM_PACKETS:
                        print(f"WARNING: One ip:{ip} appears more than {NUM_PACKETS} times!")
               
                data_offset = 0
                if conn_type == 3: # 代表可以选择ssl or CredSSP
                    # Try to unpack from unencrypted and decrypted data
                    

                    if rtt_data["connection"] != None and rtt_data["x224"] != None :
                        if rtt_data["connection"] < self.data[ip]["min_connect_rtt"]:
                            self.data[ip]["min_connect_rtt"] = rtt_data["connection"] 
                        if rtt_data["x224"] < self.data[ip]["min_x224_rtt"]:
                            self.data[ip]["min_x224_rtt"] = rtt_data["x224"] 

                else:
                    # Try to unpack from unencrypted and decrypted data
                    if not raw_data[data_offset:]:
                        self.data[ip]["is_rdp"] = False
                        self.data[ip]["why_not_is_rdp"] = NOT_RESPONSE
                        continue
                    else: 
                       
                        if not raw_data.startswith(b"\x03"):#不是03开头，不是rdp协议
                            self.data[ip]["is_rdp"] = False
                            self.data[ip]["why_not_is_rdp"] = NOT_START_WITH_03
                            continue 
                        
                         # weird xrdp data
                        if raw_data[data_offset:].startswith(b"\x03\x00\x00\x09"):
                            self.data[ip]["is_rdp"] = False
                            self.data[ip]["why_not_is_rdp"] = NOT_RDP_SERVER_XRDP
                            continue
                        # wird vbox data
                        if raw_data[data_offset:].startswith(b"\x03\x00\x00\x0b"):
                            self.data[ip]["is_rdp"] = False
                            self.data[ip]["why_not_is_rdp"] = NOT_RDP_SERVER_VBOX
                            continue 

                        try:
                            self.data[ip]["is_rdp"] = True
                            self.data[ip]["why_not_is_rdp"] = None

                            unp_data, l = formats[0].unpack(raw_data)#formats[0]是x224
                        except struct.error as e:
                            # print(ip + ":  " + str(conn_type))
                            # print("struct.error")
                            self.data[ip]["why_tls_is_none"] = 'unpackX224Error'
                            
                            continue

                        
                            
                        tls_data = raw_data[l:]#x224之后是tls协议
                        if tls_data:
                            try:
                                tls_class, tls_recordnum = tls_classify(tls_unpack(tls_data))#这里做了tls实现的分类
                            except:
                                # print('-------------------------------------')
                                # print('tls unpack default:' + ip)
                                # traceback.print_exc()
                                self.data[ip]["why_tls_is_none"] = 'unpackTLSError'
                                continue 
                            if tls_recordnum is None:
                                # print('-------------------------------------')
                                # print('tls_recordnum is None:' + ip)
                                # print(tls_data)
                                self.data[ip]["why_tls_is_none"] = 'tlsRecordnum_is_None'
                                continue
                            

                            if self.data[ip]["tls"] != None: #如果之前已经有tls记录
                                if tls_recordnum == 2 :#如果是2，表示是只有server hello，没有certificate，因为之前已经有收到certificate的TLS响应了，正常
                                    continue
                                self.data[ip]["tls"] = max(tls_recordnum, self.data[ip]["tls"])
                            else:
                                if tls_recordnum == 2 :#如果是2，但之前没有tls记录，那么就是不正常的。。。有些情况下没有记录tls_adata
                                    self.data[ip]["why_tls_is_none"] = 'not_has_cert'
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
    why_not_is_rdp_num = dict()
    # 过滤IP
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
                why_not_is_rdp_num[final_res.data[ip]["why_not_is_rdp"]] = why_not_is_rdp_num.get(final_res.data[ip]["why_not_is_rdp"], 0) + 1

            del final_res.data[ip]["counter"]
            del final_res.data[ip]["is_rdp"]
        print("totoal ip:{}".format(count))
        print('del ip:',len(todel))
        print(why_not_is_rdp_num)
        for ip in todel:#del 发送任何等级的消息，都没有回复的,以及不是rdp，其实counter==0时is_rdp也是False
            del final_res.data[ip]

        # with open("process_data_"+current_time+".csv", "w") as f:
        #     # wr = csv.DictWriter(f, fieldnames=rdp_classif_columns)
        #     writer = csv.DictWriter(f, fieldnames= ['ip','min_connect_rtt','min_x224_rtt','tls'],lineterminator='\n')
        #     for values in final_res.data.values():
        #         writer.writerow(values)
        
        rows = final_res.data.values()
        
        
        # 计算Ratio
        count = 0 
        count2 = 0
        rowlist = []

        count_tls_is_none = 0
        why_tls_is_none_num = dict()

        for row in rows:
            count+=1
            ip, connect_rtt, x224_rtt, tls, x224_response = row['ip'], row['min_connect_rtt'], row['min_x224_rtt'], row['tls'], row['x224_response']

            if tls == None  :
                count_tls_is_none += 1
                # if row['why_tls_is_none']==None:
                    # print(row)
                why_tls_is_none_num[row['why_tls_is_none']] = why_tls_is_none_num.get(row['why_tls_is_none'], 0) + 1
                continue

            x224_rtt = float(x224_rtt)
            connect_rtt = float(connect_rtt)
            ratio =   x224_rtt / connect_rtt      
            rowlist.append({'ip':ip, 'connect_rtt':connect_rtt, 'x224_rtt':x224_rtt, 'ratio':ratio, 'tls':tls, 'x224_response':x224_response}) 
            count2 +=1
        print('The total lines is ',count)
        print('The total lines is (tls != None)',count2)
        print('The total lines is (tls == None)',count_tls_is_none)
        print('why tls is none:')
        print(why_tls_is_none_num)
        
        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

        with open(args.response_log+'_proccessed.csv',"w") as all_f: 
            all_writer = csv.DictWriter(all_f, fieldnames=['ip','connect_rtt','x224_rtt','ratio','tls','x224_response' ],lineterminator='\n')
            
            # 写入列名
            all_writer.writeheader()

            for row in rowlist:
                all_writer.writerow(row)

        # 分类
        


 
if __name__ == '__main__':
    main()