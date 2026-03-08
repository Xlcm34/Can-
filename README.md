# Can日志初筛分析
先抓包：candump -l vcan0
得到 candump-xxxx.log，把它拷贝成 candump.log 或改脚本变量 
跑分析：
python analyze_candump.py
