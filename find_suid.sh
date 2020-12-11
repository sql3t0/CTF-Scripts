RED='\033[0;31m';
GRE='\033[0;32m';
BLU='\033[0;34m';
LGRE='\033[1;32m';
NC='\033[0m';
for FILENAME in $(find / -user root -perm /4000 2>/dev/null)
    ;do
        for DIR in $(ldd $FILENAME 2>/dev/null | grep '=>' | cut -d' ' -f 3 | xargs dirname 2>/dev/null | sort -u )
            ;do
                PERM=$(stat -L -c "%U" $DIR);
                if [[ "$PERM" == "root" ]];then printf "${RED}[-]${NC} `hostname`, ${GRE}$FILENAME${NC}, ${BLU}$DIR${NC}, ${RED}$PERM ${NC}\n" ;else printf "${LGRE}[+]${NC} `hostname`, ${GRE}$FILENAME${NC}, $DIR, ${LGRE}$PERM ${NC} (Priv)\n" ;fi
        ;done
    ;done