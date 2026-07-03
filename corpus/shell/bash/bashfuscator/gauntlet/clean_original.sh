#!/bin/bash
greeting="DISROBE_GAUNTLET_MARKER"
for i in 1 2 3; do
  echo "iteration ${i}: ${greeting}"
done
if [ "${greeting}" = "DISROBE_GAUNTLET_MARKER" ]; then
  printf '%s\n' "verified ${greeting}"
fi
