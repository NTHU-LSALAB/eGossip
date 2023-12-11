#!/bin/bash

# Send POST request
curl -X POST -H "Content-Type: application/json" -d '{"test-meta"}' http://192.168.3.11:8000/publish

# Start the timer
start_time=$(date +%s)

while true; do
  all_same=1  # Assume all outputs are the same initially
  prev_output=""

  for i in {11..20}
  do
    output=$(curl -s "http://192.168.3.$i:8000/metadata")
    echo "$output"
    echo " "
    
    if [ -z "$prev_output" ]; then
      prev_output="$output"
    elif [ "$prev_output" != "$output" ]; then
      all_same=0  # If any of the outputs are different, set all_same to 0
      break
    fi
  done

  # If all outputs are the same, exit the loop
  if [ "$all_same" -eq "1" ]; then
    end_time=$(date +%s)
    elapsed_time=$(($end_time - $start_time))
    echo "All outputs are the same!"
    echo "Total elapsed time: $elapsed_time seconds"
    break
  fi

  sleep 0.5  # Check every 0.5 seconds
done
