#!/bin/bash

# script to test against
cat /proc/net/dev | grep "$1" | sed -r 's/\s+/ /g' | cut -d " " -f 3,11
