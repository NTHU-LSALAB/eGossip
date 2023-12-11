#!/bin/bash

DEPLOYMENT_NAME="gossip-service"

kubectl get pods -n default -l app=$DEPLOYMENT_NAME -o wide | awk '{if(NR>1) print $6}'