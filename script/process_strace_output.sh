#!/bin/bash

FILE_NAME="strace_output.txt"

SEARCH_STRING="Type"

COUNT=$(grep -o "$SEARCH_STRING" "$FILE_NAME" | wc -l)

echo "The string '$SEARCH_STRING' appeared $COUNT times in the file $FILE_NAME."
