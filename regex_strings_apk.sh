#!/bin/bash

N='\033[0m' 
G='\033[0;32m'
Y='\033[0;33m'
WORDS="ENCODED|DECODED|USERNAME|PASSWORD|LOGIN|PASSWD|API|KEY|TOKEN|BEARER|AUTH|BASIC|USUARIO|SENHA|PWD|USER|ROOT|URL|PATH|HTTP|FLAG"
jadx="C:\PentestBox\bin\androidsecurity\jadx\bin\jadx.bat"

if [ -z "$1" ];
    then
        printf "$Y[!] Usage :$N script.sh APK_NAME"
        exit
fi

printf "$Y[>] Decompressing APK...$N\n"
$jadx --deobf "$1"  1>/dev/null
s="$1" && folder=${s/\.apk/}
cd "$folder"

printf "$Y[>] Seaching Variables...$N\n"
printf "$G[+] TABLE ( VARIABLES )$N\n"
egrep -inor "(String|int|byte(|\[\])|char) [ -~]*($WORDS)[ -~]*? = [ -~]+(;|)" . | sort -u | awk -F':' 'BEGIN{ printf "[+] %s# %s# %s# %s#\n","LINE","FILENAME","VARIABLE","VALUE"}{gsub(/^\t/,"",$3); gsub(/=/,"#",$3); print "[+] "$2"# "$1"# "$3"#"} ' | column -t -s"#" -o "|"

printf "\n$Y[>] Seaching IF Statements...$N\n"
printf "$G[+] TABLE ( IF STATEMENTS )$N\n"
egrep -inor "(if\(|if[ ]+\()[ -~]*($WORDS)[ -~]*(==|===|>=|<=|>|<|!=)[ -~]+" . | sort -u | awk -F "if" '{print $1$2}' | awk -F':' 'BEGIN{ printf "[+] %s# %s# %s\n","LINE","FILENAME","COMPARATION" }{print "[+] "$2"# "$1"# "$3}' | column -t -s"#" -o "|"

printf "\n$Y[>] Seaching SQL Querys...$N\n"
printf "$G[+] TABLE ( SQL QUERYS )$N\n"
egrep -onr "?(SELECT|INSERT|UPDATE) [ -~]+ (FROM|(INTO|INTO[ -~])|SET) [ -~]*" . | sort -u | awk -F":" 'BEGIN{ printf "[+] %s# %s # %s\n","LINE","FILENAME","QUERY" }{print "[+] "$2"# "$1"# "$3}' | column -t -s"#" -o "|"

REMOVER="y" #DefaultValue
printf "\n$Y[?]$N Delete Decompiled APK Folder [Y/n]: "
read REMOVER
if [ "$REMOVER" = "y" ] || [ "$REMOVER" = "Y" ];
    then
        cd - 1>/dev/null && rm -rf "$folder" && printf "$G[+] Successfully removed.$N\n"
    else
        cd - 1>/dev/null
fi
