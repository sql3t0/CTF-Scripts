#!/bin/bash
#bySql3t0
if [ $# -eq 0 ]
then
	echo "Use: $0 <luks_filename> <wordlist>"
	exit 0
else	
	printf '\n'
	while read p
	do 
		printf "\r Senha: $p                                                           "
		if echo $p | cryptsetup luksOpen $1 luks_decrypted_file  2>&1 | wc -l | grep '0'
		then
			echo "[+]Passwd FOUND : $p";
			sleep 5
			umount /dev/mapper/luks_decrypted_file
			cryptsetup luksClose luks_decrypted_file
			exit 0
		fi
	done < "$2" 
fi
printf '\n [-] Passwd NOT found !! \n'
