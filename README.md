# RDP mitm 测量

## 1、开始扫描
```
zmap -p 3359 | python3 RDP_scan_asyncio.py
```

## 2、扫描数据处理
```
python3 myRDP_classify_new.py --response_log {sacn_result.csv}
```

## 3、分类器分类
使用随机森林预测代码进行分类，得到测量结果