#!/bin/sh

read -s -p "Senha:" senha
senha=$(printf "$senha" | sha1sum | cut -d' ' -f1)
printf "\rHASH -> %s\n" "$(curl -k -s https://api.pwnedpasswords.com/range/${senha:0:5} | grep -i ${senha:6:40})"