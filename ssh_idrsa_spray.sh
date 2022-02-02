#!/bin/bash

RST='\e[0m'
CLG='\e[92m'
CLY='\e[93m'

if [ "$#" -gt 2 ]; then
    printf "$CLY\nStarting...\n$RST"
    printf "$CLY%$(tput cols)s\n$RST" | tr " " "_"
    for ip in $(fping -Aaq -r 1 -g $3)
    do
        printf "\rIP: $ip"
        ssh -i $2 $1@$ip \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=2 \
        'printf "\r'$CLG$ip$RST' | $(hostname) | $(id)\n"' \
        2>/dev/null
    done
    printf "\n$CLY%$(tput cols)s\n$RST" | tr " " "_"
    printf "$CLY\nEnd.$RST\n"
else
    printf "\n$CLY[!] Usage:$RST\n"
    printf "         : $0 username privk_id_rsa_file CDIR\n"
    printf "         : Eg. $0 root ~/.ssh/id_rsa 192.168.0.1/24\n\n"
fi
