@ECHO OFF
REM .bat pra alterar/personalizar o background de logon do Window 7
REM Essa personalizacao de Backgroun soh funcoina se excutada como administrador
REM A imagem deve ser do tipo .jpg e ter no maximo 256KB de tamanho em disco 

if [%~1]==[] (goto :Usage) ELSE ( goto :EditRegister )
	:Usage
		ECHO Modo de usar:
		ECHO 	Abra o CMD.exe como Administrador e execute o comando abaixo.
		ECHO 	%0 Nome\DaImagem\PraUsar\Como\Background.jpg
		PAUSE
		EXIT /B
	:EditRegister
		REM Ativa a chave de mudanca de background personalizado
		CALL REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background /t REG_DWORD /v OEMBackground /d 1 /f

		if %ERRORLEVEL% == 0 goto :CreateDir
			ECHO Erro na ativacao da chave de registro.
			ECHO Obs: Voce deve executar o script %0 com permissao de Administrador.
			EXIT /B
		:CreateDir
			REM Cria o diretorio onde eh lida a img default de background
			CALL MKDIR C:\Windows\System32\oobe\info\backgrounds

			if %ERRORLEVEL% == 0 ( goto :MoveImg ) ELSE ( goto :MoveImg )
				ECHO Erro na criacao da pasta C:\Windows\System32\oobe\info\backgrounds . 
				ECHO Obs: Voce deve executar o script %0 com permissao de Administrador.
				EXIT /B
			:MoveImg
				REM Renomeia e move o .jpg para a pasta criada anteriormente.
				CALL COPY %1 C:\Windows\System32\oobe\info\backgrounds\backgroundDefault.jpg
				if %ERRORLEVEL% == 0 goto :Sucess
					ECHO Erro ao copiar a imagem .jpg para a pasta C:\Windows\System32\oobe\info\backgrounds\
				:Sucess
					ECHO Altercao concluida com Sucesso. Tecle CTRL+L e veja o resultado.
					PAUSE
