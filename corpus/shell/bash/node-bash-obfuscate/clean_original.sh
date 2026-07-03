#!/usr/bin/env bash
GREETING='hello world'
echo "$GREETING"
for i in 1 2 3; do
  echo "line $i"
done
printf 'done:%s\n' "$GREETING"
