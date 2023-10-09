#!/bin/bash

curl -X POST -H "Content-Type: application/json" -d '{"test-meta-11"}' http://192.168.3.11:8000/publish
sleep 1
curl -X POST -H "Content-Type: application/json" -d '{"test-meta-12"}' http://192.168.3.11:8000/publish
sleep 1
curl -X POST -H "Content-Type: application/json" -d '{"test-meta-13"}' http://192.168.3.11:8000/publish
sleep 1
curl -X POST -H "Content-Type: application/json" -d '{"test-meta-14"}' http://192.168.3.11:8000/publish