if [ $# -lt 2 ]
	then
    	echo "Usage : $0 file.zip wordlist.txt "
    	exit 1
	else
		while read p;do printf "\r [>] Pass : $p 	";if 7z e -y "$1" -p"$p" 2>/dev/null | grep "Everything is Ok";then echo " [+] Passwd Found : $p ";break;fi;done < "$2"	
fi
