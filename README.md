# Emotet C2 Extract

EmotetのC2通信先を抽出するPythonのスクリプトです。
@hasherezade氏のPE-Sieveを使ってEmotetのプロセスから抽出します。

(2022/11/2追記)：次の検体でC2通信先が抽出できることを確認しています。確認した検体は次のハッシュ値(deb051590b0b91fe92342dd703db1aa4)

# 使い方
Python3.7以上をインストールした安全な環境(VM)などを用意してください。

このスクリプトはpefileとyara-pythonを使っています。インストールは次の通り
```
> pip install pefile yara-python
```

:warning:　実際にEmotetを動作させて抽出するので、スナップショットをとっておいたほうが良いです　:warning:

このリポジトリをダウンロードしたら、EmotetのDLLを実行します(regsvr32.exeで実行すればよいです。)
```
C:\> regsvr32.exe emotet.dll
```

Emotetのプロセスが動いているPID見つけて、Pythonスクリプトを動かせばC2情報を抽出します。
EmotetのPIDはProcess HackerやProcess Monitorを使って見つけてください。
```
C:\> python .\Emotet_C2_extractor.py --pid 7916 --o ".\c2.txt"
[+] Emotet C2's:
64.227.55.231:8080
196.44.98.190:8080
54.37.106.167:8080
77.112.31.114:33561
210.57.209.142:8080
195.77.239.39:8080
51.19.250.254:48699
52.156.146.25:45651
75.18.92.182:30268
139.196.72.155:8080
87.106.97.83:7080
175.126.176.79:8080
85.25.120.45:8080
112.170.30.29:35842
165.22.254.236:8080
59.148.253.194:443
75.108.162.28:56225
20.106.42.138:14992
88.217.172.165:8080
103.41.204.169:8080
37.44.244.177:8080
48.6.75.103:49226
60.130.1.93:62534
202.134.4.210:7080
62.171.178.147:8080
103.56.149.105:8080
118.98.72.86:443
103.224.241.74:8080
202.28.34.99:8080
157.230.99.206:8080
198.199.70.22:8080
0.0.0.0:0
85.214.67.203:8080
99.54.222.184:12877
188.225.32.231:4143
54.37.228.122:443
36.67.23.59:443
202.29.239.162:443
78.47.204.80:443
104.244.79.94:443
53.117.165.252:19815
165.22.254.68:443
18.73.65.76:7883
110.137.224.201:14762
101.57.61.115:31780
116.124.128.206:8080
157.245.111.0:8080
68.183.91.111:8080
93.104.209.107:8080
105.133.164.82:27813
178.62.112.199:8080
103.71.99.57:8080
48.75.13.174:45107
128.199.217.206:443
103.85.95.4:8080
104.248.225.227:8080
68.236.93.102:26002
75.26.230.10:62581
41.6.57.15:31238
103.254.12.236:7080
55.208.180.184:19355
103.126.216.86:443
165.232.185.110:8080
72.240.66.224:38505
```

--helpオプションで使い方を見ることができます。なお、Emotetは64bitのDLLなので、--is32bitオプションは使わないです。
```
> python .\Emotet_C2_extractor.py --help
usage: Emotet_C2_extractor.py [-h] --pid TARGET_PID [--o OUTPUT_FILE]
                              [--is32bit]

Emotet C2's Extractor only tested 64bit environment

optional arguments:
  -h, --help        show this help message and exit
  --pid TARGET_PID  PID of the process running the Emotet
  --o OUTPUT_FILE   Filename of the output file
  --is32bit         Specify this flag if the target process is a 32-bit
                    process
```
# Emotet C2 Extract[English]
Python script to extract the C&C configuration from an active Emotet process through PE-Sieve.

Based on [PE-Sieve](https://github.com/hasherezade/pe-sieve) work made by [@hasherezade](https://github.com/hasherezade).

# Configuration
To extract the Emotet C2 you need a safe environment (such as a virtualized system) with an installed Python 3.7 or higher.  

Be sure to make a snapshot of the environment before proceeding with the execution of the Emotet DLL!

This script uses yara-python and pefile. You can install these module with pip.
```
> pip install pefile yara-python
```

Cloned the repository, run the Emotet DLL (for example through the Windows utility regsvr32.exe) 
```
C:\> regsvr32.exe emotet.dll
```
Find the PID of the running Emotet process (for example through Process Hacker or Process Monitor) and run the Python script to extract the C&C configuration:
```
C:\> python .\Emotet_C2_extractor.py --pid 7916 --o ".\c2.txt"
[+] Emotet C2's:
64.227.55.231:8080
196.44.98.190:8080
54.37.106.167:8080
77.112.31.114:33561
210.57.209.142:8080
195.77.239.39:8080
51.19.250.254:48699
52.156.146.25:45651
75.18.92.182:30268
139.196.72.155:8080
87.106.97.83:7080
175.126.176.79:8080
85.25.120.45:8080
112.170.30.29:35842
165.22.254.236:8080
59.148.253.194:443
75.108.162.28:56225
20.106.42.138:14992
88.217.172.165:8080
103.41.204.169:8080
37.44.244.177:8080
48.6.75.103:49226
60.130.1.93:62534
202.134.4.210:7080
62.171.178.147:8080
103.56.149.105:8080
118.98.72.86:443
103.224.241.74:8080
202.28.34.99:8080
157.230.99.206:8080
198.199.70.22:8080
0.0.0.0:0
85.214.67.203:8080
99.54.222.184:12877
188.225.32.231:4143
54.37.228.122:443
36.67.23.59:443
202.29.239.162:443
78.47.204.80:443
104.244.79.94:443
53.117.165.252:19815
165.22.254.68:443
18.73.65.76:7883
110.137.224.201:14762
101.57.61.115:31780
116.124.128.206:8080
157.245.111.0:8080
68.183.91.111:8080
93.104.209.107:8080
105.133.164.82:27813
178.62.112.199:8080
103.71.99.57:8080
48.75.13.174:45107
128.199.217.206:443
103.85.95.4:8080
104.248.225.227:8080
68.236.93.102:26002
75.26.230.10:62581
41.6.57.15:31238
103.254.12.236:7080
55.208.180.184:19355
103.126.216.86:443
165.232.185.110:8080
72.240.66.224:38505
```

For further script arguments execute the script with the --help flag:
Emotet DLL is 64-bit binary. So --is32bit flag may be unnecessary.
```
> python .\Emotet_C2_extractor.py --help
usage: Emotet_C2_extractor.py [-h] --pid TARGET_PID [--o OUTPUT_FILE]
                              [--is32bit]

Emotet C2's Extractor only tested 64bit environment

optional arguments:
  -h, --help        show this help message and exit
  --pid TARGET_PID  PID of the process running the Emotet
  --o OUTPUT_FILE   Filename of the output file
  --is32bit         Specify this flag if the target process is a 32-bit
                    process
```
