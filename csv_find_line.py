import json
import pandas as pd
from tqdm import tqdm

def find_line_by_ip(file_path, ip):

    

    # 设置一个合适的chunk size来分块读取大文件
    chunk_size = 500000  # 这里是每次读取10万行

    # 如果没有列名，指定 names 参数
    column_names = ['ip', 'connect_type', 'rtt', 'raw_data', 'enc_data', 'tls_data']

    # 使用 header=None 来告诉 pandas 文件没有列名
    chunks = pd.read_csv(file_path,  names=column_names, header=None, chunksize=chunk_size)

    filtered_rows = []

    # 遍历每个块，筛选出符合条件的行
    for chunk in chunks:
        filtered_rows.append(chunk[chunk['ip'] == ip])

    # 设置最大显示的行数和列数为 None（显示所有行和列）
    pd.set_option('display.max_rows', None)  # 显示所有行
    pd.set_option('display.max_columns', None)  # 显示所有列
    pd.set_option('display.width', None)  # 自动调整宽度
    pd.set_option('display.max_colwidth', None)  # 显示列的最大宽度
    pd.set_option('display.max_seq_item', None)  # 长序列不被截断

    # 合并所有匹配行
    result = pd.concat(filtered_rows)

    # 打印最终的匹配结果
    print(result)
    # 将结果保存到 CSV 文件
    result.to_csv('filtered_result.csv', index=False)

def print_top_n_lines(file_path, n):
    # 读取CSV文件的前100行
    # file_path = 'file_path'  # 请替换为你实际的CSV文件路径
    df = pd.read_csv(file_path, nrows=n)

    # 获取第2列的数据，并按该列去重
    second_column = df.iloc[:, 1].drop_duplicates()
    second_column_list = second_column.tolist()
    # 打印前100行的第2列并去重
    print(len(second_column_list))
    ip_data_lookup(second_column_list)

def print_lines(file_path):
    # 读取CSV文件的前100行
    # file_path = 'file_path'  # 请替换为你实际的CSV文件路径
    df = pd.read_csv(file_path)

    # 获取第2列的数据，并按该列去重
    second_column = df.iloc[:, 1]
    second_column_list = second_column.tolist()
    # 打印前100行的第2列并去重
    print(second_column_list)


import requests
def ip_hostname_lookup(ips):
    ip_domain_dict = {}
    has_hostname_num = 0
    for ip in ips:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        ip_data = response.json()
        print(ip_data)
        if  "hostname" in ip_data: # 获取 IP 反查结果
            ip_domain_dict[ip] = ip_data["hostname"]
            has_hostname_num += 1
        else:
            ip_domain_dict[ip] = "None"
    print(ip_domain_dict)
    print(f"Total IP: {len(ips)}")
    print(f"Total IP with hostname: {has_hostname_num}")

def ip_data_lookup(ips):
    ip_domain_dict = {}
    has_hostname_num = 0
    for ip in tqdm(ips):
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        ip_data = response.json()
        print(ip_data)
        ip_domain_dict[ip] = ip_data
    print(ip_domain_dict)

    with open('ip_data_lookup_all0313.json', 'w') as f:
        json.dump(ip_domain_dict, f)

def print_top_n_lines_json(file_path):
    with open(file_path, 'r') as f:
        jarm_dict = json.load(f)
    ip_list = []
    for jarm, data in jarm_dict.items():
        print(jarm)
        if jarm in ['21d14d00021d21d21c21d14d21d21d', '04d02d00004d04d04c04d02d04d04d', '21d14d00021d21d00021d14d21d21d']:
            for item in data:
                print(item)
                ip_list.append(item['ip'])
    print(len(ip_list))
    ip_data_lookup(ip_list)

def data_lookup(file_path):
    dict_org = {}
    with open(file_path, 'r') as f:
        ip_data_dict = json.load(f)
    for ip, data in ip_data_dict.items():
        if data['org'] not in dict_org:
            dict_org[data['org']] = []
        if 'hostname' not in data:
            dict_org[data['org']].append([data['ip'], "hostname is Nonen", data['city']+'-'+data['region']+'-'+data['country']])
        else:
            dict_org[data['org']].append([data['ip'], data['hostname'],data['city']+'-'+data['region']+'-'+data['country']])
    print(dict_org)
    with open('ip_data_lookup_org_all0313.json', 'w') as f:
        json.dump(dict_org, f)
    for org, data in dict_org.items():
        print(org, len(data))
        print()
        print()
        # for item in data:
        #     print(item)

def latex_table():
    with open('ip_data_lookup_org.json', 'r') as f:
        ip_data_dict = json.load(f)
    # 示例 Python 列表
    data = []
    count = 1
    for org, data2 in ip_data_dict.items():
        for item in data2:
            data.append((count, item[0],  item[2], org.split(" ")[0] ,''))
            count += 1
            print(count)
    # data = [
    #     (1, "171.xxx.70.80", "美国加利福尼亚州", "AS 32", "Stanford University"),
    #     (2, "171.xxx.71.40", "美国加利福尼亚州", "AS 32", "Stanford University"),
    #     (3, "92.xxx.161.5", "法国巴黎", "AS 3356", "Netsystems"),
    #     (4, "92.xxx.161.1", "法国巴黎", "AS 3356", "Netsystems"),
    #     # 继续你的数据...
    # ]

    # 生成 LaTeX 表格代码
    latex_code = "\\begin{table}[ht]\n\\centering\n\\caption{The real scanner identified}\n\\begin{tabular}{|c|c|c|c|c|}\n\\hline\n"
    latex_code += "# & RDP中间人IP 地址 & 地理位置 & ASN 数据 & 所属类别 \\\\ \\hline\n"

    for row in data:
        latex_code += " & ".join(str(x) for x in row) + " \\\\ \\hline\n"

    latex_code += "\\end{tabular}\n\\end{table}"

    # 输出生成的 LaTeX 代码
    print(latex_code)





if __name__ == '__main__':
    # file_path = 'D:\\rdpData\\test20250219.csv'
    # ip = '99.235.66.46'
    # find_line_by_ip(file_path, ip)

    # file_path = 'D:\\rdpData\\test20250219.csv_proccessed_classify-class1.csv'
    
    # print_top_n_lines(file_path, 200)
    # file_path = 'ip_data_lookup_all0313.json'
    # data_lookup(file_path)

    # latex_table()
    print_lines('D:\\rdpData\\test20250219.csv_proccessed_classify-class1.csv')