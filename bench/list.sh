#!/bin/bash

for i in {11..20}
do
  # 使用curl發起HTTP請求並將結果儲存到變數json_data中
  json_data=$(curl -s "http://192.168.3.$i:8000/list")
  
  # 檢查curl命令的退出狀態以確保請求成功
  if [ $? -eq 0 ]; then
    # 使用jq解析JSON數據並計算IP地址數量
    ip_count=$(echo "$json_data" | jq '.[] | .Addr' | wc -l)
    
    # 顯示該次請求的總結信息
    echo "HTTP request to 192.168.3.$i Summary:"
    echo "---------------------------------------"
    echo "Number of IP addresses in the response: $ip_count"
    # echo "IP Addresses:"
    # echo "$json_data" | jq -r '.[] | .Addr'
    echo "---------------------------------------"
  else
    echo "Failed to retrieve data from 192.168.3.$i"
  fi
done
