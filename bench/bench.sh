#!/bin/bash

#cd ../ && docker-compose up -d

#cd bench

sleep 5

server_count=2
for i in {12..20}
do
  server_name="server$server_count"
  echo "192.168.3.$i"
  echo $server_name
  curl -X POST -H "Content-Type: application/json" \
       -d "{\"Addr\":\"192.168.3.$i\",\"Port\":8000,\"Name\":\"$server_name\",\"PrivateData\":\"test-data\", \"LinkName\":\"eth0\"}" \
       "http://192.168.3.11:8000/set"
  server_count=$((server_count+1))
  #sleep 1
done



sleep 1800

cd ../ && docker-compose down

#curl -X POST -H "Content-Type: application/json" -d '{"Addr":"192.168.3.12","Port":8000,"Name":"server2","PrivateData":"test-data", "Linkname":"eth0"}' http://192.168.3.11:8000/set
#curl -X POST -H "Content-Type: application/json" -d '{"Addr":"192.168.3.12","Port":8000,"Name":"server2","PrivateData":"test-data", "Linkname":"eth0"}' http://192.168.3.11:8000/set
#curl -X POST -H "Content-Type: application/json" -d '{"Addr":"192.168.3.13","Port":8000,"Name":"server1","PrivateData":"test-data"}' http://192.168.3.11:8000/set


# sleep 20


# total_requests=$((30/2))

# for (( i=0; i<$total_requests; i++ )); do
#     random_string=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 16 | head -n 1)
    
#     curl -X POST -H "Content-Type: application/json" -d "{\"$random_string\"}" http://192.168.3.11:8000/publish

#     sleep 1
# done



# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-11"}' http://192.168.3.11:8000/publish
# sleep 1
# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-12"}' http://192.168.3.11:8000/publish
# sleep 1
# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-13"}' http://192.168.3.11:8000/publish
# sleep 1
# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-14"}' http://192.168.3.11:8000/publish



# curl -X POST -H "Content-Type: application/json" -d '{"test-meta"}' http://192.168.3.11:8000/publish
# sleep 0.2
# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-1"}' http://192.168.3.11:8000/publish
# sleep 0.2
# curl -X POST -H "Content-Type: application/json" -d '{"test-meta-23"}' http://192.168.3.13:8000/publish
