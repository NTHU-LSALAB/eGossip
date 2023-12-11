#!/bin/bash

num_containers=3 

for ((i=1; i<=num_containers; i++))
do
    container_name="gossip_service$i"
    
    > "${container_name}_logs.txt"
   
    docker-compose logs "$container_name" >> "${container_name}_logs.txt"
done

