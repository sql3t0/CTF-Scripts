#!/bin/bash
# 
# Script to hook some libc.so functions 
#
# sudo apt-get update
# sudo apt-get install gcc-multilib
#

if [ -z "$1" ]
	then 
		echo "[!] ELF-Name parameter is required !"
		echo "[>] Egg: $0 crackme" 
		exit
fi

if file $1 | grep -o '64-bit';then arch=64;else arch=32;fi
echo "Running '$1' $arch-bit..."

gcc -shared -o hook.so -m$arch -x c - <<EOF
#include <stdio.h>
#include <string.h>

long ptrace(int request, int pid, void *addr, void *data)
{
	return 0;
}

int strcmp(const char *str1, const char *str2)
{
	printf("strcmp : <%s> <%s> \n", str1, str2);
	while(*str1)
	{
		if (*str1 != *str2)
			break;

		str1++;
		str2++;
	}

	//return 0; 
	return *(const unsigned char*)str1 - *(const unsigned char*)str2;
}

int strncmp(const char *str1, const char *str2, size_t n){
	printf("strncmp : <%s> <%s>", str1, str2);
	return 0;
}

size_t strlen(const char *str){
	printf("strlen : <%s>", str);
	int s = 0;
	while (*str++) s++;
	printf(" : <%d>\n", s);
	return s;
}

unsigned int sleep(unsigned int seconds){
	printf("\nSleep: Hooked");
	return 0;
}

char *strcpy(char* destination, const char* source)
{
	printf("strlen : <%s> <%s> ", source, destination);
	if (destination == NULL)
		return NULL;

	char *ptr = destination;

	while (*source != '\0')
	{
		*destination = *source;
		destination++;
		source++;
	}

	*destination = '\0';

	return ptr;
}

char *strncpy(char *dest, const char *src, size_t n)
{
	printf("strlen : <%s> <%s> <%d>", src, dest, n);

	size_t i;
	for (i = 0; i < n && src[i] != '\0'; i++)
		dest[i] = src[i];
	for ( ; i < n; i++)
		dest[i] = '\0';

	return dest;
}
EOF

LD_PRELOAD=./hook.so ./$1 


# By Sql3t0
