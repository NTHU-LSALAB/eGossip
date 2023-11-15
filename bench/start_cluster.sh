#!/bin/bash

server_count=10

ip_base=11
mac_base="02:42:ac:12:00:"

for ((i=0; i<server_count-1; i++)); do
  server_name="server$((i + 2))" 

  ip="192.168.3.$((ip_base + i + 1))"
  mac="${mac_base}$(printf '%02d' $((i + 2)))"  

  echo "Configuring $server_name with IP $ip and MAC $mac"

  curl -X POST -H "Content-Type: application/json" \
       -d "{\"Addr\":\"$ip\",\"Port\":8000,\"Mac\":\"$mac\",\"Name\":\"$server_name\",\"PrivateData\":\"test-data\", \"LinkName\":\"eth0\"}" \
       "http://192.168.3.11:8000/set"
done
