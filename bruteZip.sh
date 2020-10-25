#!/bin/bash
# Bruteforce Zip files Toll Atack
#By Sql3t0
echo " ---------------------------------"
echo "|           BRUTE_ZIP             |"
echo " ---------------------------------"

if [ "$1" == "" ] || [ "$2" == "" ]; then 
	echo "Usage : ./script.sh 'file_name.zip' 'wordlist_path' ";
else
	newDir=$(echo "$1" | tr . _ )
	mkdir $newDir 2> /dev/null > /dev/null || echo "Directory Name ($newDir) Exists ! [ Replacing Files Now ] ";
	echo "fixed dir" > $newDir/.fixed
	while read pass; 
	do 
	  	printf "\r Testing PASSWD : $pass";
	 	unzip -o -P $pass $1 -d $newDir/$pass 2> /dev/null > /dev/null;
	 	rm -d $newDir/$pass 2> /dev/null || printf "\r FOUND PASSWD : $pass                \n"  ; 

	done < $2;
	rm $newDir/.fixed
	printf "\r - FINISHED -                                                                \n"
fi