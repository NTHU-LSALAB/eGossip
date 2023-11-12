#!/bin/bash

server_count=3

ip_base=110
mac_base="02:42:ac:12:00:"

for ((i=0; i<server_count-1; i++)); do
  server_name="server$((i + 2))" 

  ip="10.121.240.$((ip_base + i))"
  mac="${mac_base}$(printf '%02d' $((i + 2)))"  

  echo "Configuring $server_name with IP $ip and MAC $mac"

  curl -X POST -H "Content-Type: application/json" \
       -d "{\"Addr\":\"$ip\",\"Port\":8000,\"Name\":\"$server_name\",\"PrivateData\":\"test-data\", \"LinkName\":\"eth0\"}" \
       "http://10.121.240.110:8000/set"
done
