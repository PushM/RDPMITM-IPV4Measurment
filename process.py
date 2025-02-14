import csv
filename='process_data.csv'
count = 0 
count2 = 0
rowlist = []
with open (filename,'r') as f:
    csv_reader = csv.reader(f)
    for row in csv_reader:
        count+=1
        ip, connect_rtt, x224_rtt, tls = row
        if tls == '' :
            continue
        x224_rtt = float(x224_rtt)
        connect_rtt = float(connect_rtt)
        ratio =   x224_rtt / connect_rtt      
        rowlist.append({'ip':ip, 'connect_rtt':connect_rtt, 'x224_rtt':x224_rtt, 'ratio':ratio, 'tls':tls })
        count2 +=1
print('The total lines is ',count)
print(count2)

# with open('/root/rdp_scan/scans_22_11_23_01_03_40/head100000.csv', "w") as f:
#     #wr = csv.DictWriter(f, fieldnames=['ip', 'type', 'rtt', ''])
#     writer = csv.writer(f)
#     for value in rowlist:
#         writer.writerow(value)

all_f = open('final_data.csv', 'w')
all_writer = csv.DictWriter(all_f, fieldnames=['ip','connect_rtt','x224_rtt','ratio','tls' ],lineterminator='\n')
    
for row in rowlist:
    all_writer.writerow(row)
all_f.close()