#!/bin/bash

for i in {11..20}
do
  json_data=$(curl -s "http://192.168.3.$i:8000/list")
  
  if [ $? -eq 0 ]; then

    ip_count=$(echo "$json_data" | jq '.[] | .Addr' | wc -l)

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
