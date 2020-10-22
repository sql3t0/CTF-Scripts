#!/bin/bash
#
# Script to solve HackTheBox chall : BombSlanded
#

if [ -z "$1" ]
	then 
		echo "[!] ELFName parameter is required !"
		echo "[>] Egg: $0 BombSlanded" 
		exit
fi

echo "Running '$1' ..."

gcc -shared -o bypass.so -m32 -x c - <<EOF
#include <stdio.h>
#include <string.h>

long ptrace(int request, int pid, void *addr, void *data) {
	return 0;
}

int strcmp(const char *str1, const char *str2){
	printf("strcmp : <%s> <%s>", str1, str2);
	return 0;
}

int strncmp(const char *str1, const char *str2, size_t n){
	printf("strncmp : <%s> <%s>", str1, str2);
	return 0;
}
EOF

echo X | LD_PRELOAD=./bypass.so ./$1 a b c d && echo 