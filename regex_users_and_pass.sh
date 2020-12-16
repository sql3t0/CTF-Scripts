#!/bin/bash
#for ip in $(cat ips_ssh);do sshpass -p "P4ssw0rd!" ssh -o StrictHostKeyChecking=no username@$ip 'bash -s' < regex_users_and_pass.sh;done


printf "\n[>] Procurando Credenciais em : `hostname` ...\n"
for dir in $(find / -maxdepth 2 -type d 2>/dev/null | egrep -v "proc/|/lib|/bin|/sbin|lib*/|boot|mnt/|^/$" | egrep -v "^/\w+$")
    do
        PatternUser="user|username|user-name|usuario|login|mail|email"
        PatternPass="pw|pass|passw|passwd|password|senha|creds|secret"
        PatternMixx="host|ldap"
        RegexFull="([\"\'\[\(\{\$]?)($PatternUser|$PatternPass|$PatternMixx)([\"\'\]\)\}\$]?)([ ]?)([:=])([ ]?)([\"\'\[\(\{])(.*)([\"\'\]\)\}])|([<])($PatternUser|$PatternPass|$PatternMixx)([>])(.+)([\/>])"
        filename=$(egrep --exclude-dir={lib,bin,sbin,proc,boot,mnt} -irl "$RegexFull" $dir 2>/dev/null)
        if [ ! -n "$filename" ]
            then
                printf "\r[+] Hostname: `hostname`  , Folder: $dir"
            else
                printf "\r[+] Hostname: `hostname`  , Folder: $dir \n";
                egrep --color=always -aino "([\"\'\[\(\{\$]?)($PatternUser|$PatternPass|$PatternMixx)([\"\'\]\)\}\$]?)([ ]?)([:=])([ ]?)([\"\'\[\(\{])(.*)([\"\'\]\)\}])|([<])($PatternUser|$PatternPass|$PatternMixx)([>])(.+)([\/>])" $filename 2>/dev/null | cut -b 1-300 | uniq &
            fi    
    done
