#!/bin/bash

if ! command -v socat &> /dev/null
then
    echo "socat tool could not be found"
    sudo apt update && sudo apt install socat
fi

YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'
DATETIME=$(date '+%d/%m/%Y %H:%M:%S')
DISPOSITIVO=/dev/ttyACM0

LISTAOP=`echo AT+COPS=? | socat - $DISPOSITIVO,echo=0,crnl`
RECEIVEDSMS=`echo 'AT+CMGL="ALL"' | socat - $DISPOSITIVO,echo=0,crnl`
OPATIVA=`echo AT+COPS? | socat - $DISPOSITIVO,echo=0,crnl`
CONN=`echo AT | socat - $DISPOSITIVO,echo=0,crnl`
NOME=`echo ATI | socat - $DISPOSITIVO,echo=0,crnl`
FABRICANTE=`echo AT+GSV | socat - $DISPOSITIVO,echo=0,crnl`
SERIAL=`echo AT+GSN | socat - $DISPOSITIVO,echo=0,crnl`
STATUS=`echo AT+CPIN? | socat - $DISPOSITIVO,echo=0,crnl`
FONE=`echo AT+CIMI | socat - $DISPOSITIVO,echo=0,crnl`

echo -e "\n${YEL}Comunicacao: ${NC} $(echo $CONN|tr '\n' ' ')"
echo -e "${YEL}Nome do Produto: ${NC} $(echo $NOME|tr '\n' ' ')"
echo -e "${YEL}Fabricante: ${NC} $(echo $FABRICANTE|tr '\n' ' ')"
echo -e "${YEL}Serial: ${NC} $(echo $SERIAL|tr '\n' ' ')"
echo -e "${YEL}Status do SIM CARD: ${NC} $(echo $STATUS|tr '\n' ' ')"
echo -e "${YEL}Numero do Telefone: ${NC} $(echo $FONE|tr '\n' ' ')"
echo -e "${YEL}Operadoras Disponiveis: ${NC}"
echo -e "$LISTAOP"
echo -e "${YEL}Operadora Ativa: ${NC} $(echo $OPATIVA|tr '\n' ' ')"
echo -e "${YEL}Todos os SMSs Recebidos: ${NC} "
echo -e "$RECEIVEDSMS\n"


SMSENCODE=`echo AT+CSCS="GSM" | socat - $DISPOSITIVO,echo=0,crnl`
echo -e "${YEL} SMS Encode: ${NC} $(echo $SMSENCODE|tr '\n' ' ')"
SMSMODE=`echo AT+CMGF? | socat - $DISPOSITIVO,echo=0,crnl`
echo -e "${YEL}Modo SMS Ativo: ${NC} $(echo $SMSMODE|tr '\n' ' ')"
echo -e "${BLU}Setando SMS em modo de Texto...${NC}"
SETSMSMODE=`echo AT+CMGF=1 | socat - $DISPOSITIVO,echo=0,crnl`
SMSMODE=`echo AT+CMGF? | socat - $DISPOSITIVO,echo=0,crnl`
echo -e "${YEL}Modo SMS Ativo: ${NC} $(echo $SMSMODE|tr '\n' ' ')"

echo -e "${BLU}Enviando SMS...${NC}"
MENSAGEM=$(cat <<-END
AT+CMGS="85987654321"
WAIT=3
Mensagem de teste $DATETIME
END
)

echo AT+CMGS="85987654321" | socat - $DISPOSITIVO,echo=0,crnl
echo WAIT=3 | socat - $DISPOSITIVO,echo=0,crnl
echo Mensagem de teste $DATETIME | socat - $DISPOSITIVO,echo=0,crnl
SMSSTATUS=`echo -e "\x1a" | socat - $DISPOSITIVO,echo=0,crnl`
echo -e "${YEL}STATUS SMS: ${NC} "
echo -e "$SMSSTATUS\n"
