#!/bin/sh

args="$@"

start=1
end=10

echo "snapraid command & arguments: $args"

for ((i=start; i<=end; i++)); do
    sleep 0.5
    echo "add $i"
done

exit 0
