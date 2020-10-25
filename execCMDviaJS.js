var shell = new ActiveXObject( "WScript.shell" );
shell.run( '"C:\\Windows\\System32\\cmd.exe" /K netstat & pause', 1, true ); //para ocultar a execução basta trocar o parametro de valor '1' por '0'