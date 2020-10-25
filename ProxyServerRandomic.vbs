
'#                    Dev. by JJ                       #

public proxy

valUserInit = MsgBox("Deseja Iniciar o Proxy ?",4,"ProxyServer Randomize 1.0")

If valUserInit=vbYes Then
   msgbox("ProxyServer Randomizer[INICIADO] !")
   Call laco  
Else
   msgbox("ProxyServer Randomizer [CANCELADO] !")
   WScript.Quit
End If


'______________________________________________________

Sub laco()

  i = 1
  x = 0
   
  Do While i <> x
     
     Call setNewProxy 
     
     AckTime = 5
     valUserEnd = WScript.CreateObject("WScript.Shell").Popup("Para Encerrar o ProyServer Select [YES] ?", AckTime, "ProyServer [" & proxy & "] ?",4)
     If valUserEnd=vbYes Then
        i = 0
        msgBox("ProxyServer Encerrado Com Sucesso !")
        Call endProxyServer
     End If  

  Loop

End Sub

'________________________________________________________

Sub setNewProxy()
          
     Randomize
     opc=int(rnd*2) + 5

     s = "191.252.177.42:8080,157.55.201.42:8080,157.245.182.232:8080,177.125.148.26:8080,177.66.54.199:8080,185.255.47.142:8080,183.88.77.25:8080,81.182.211.107:8080,93.125.45.1:8080,177.91.219.28:8080,39.108.123.4:3128,177.99.206.82:8080,200.192.255.102:8080,177.124.75.52:3128,143.255.54.136:8080,213.6.77.118:8080,168.195.231.136:8080,177.67.39.57:8080"
     ips = Split(s, ",")
     proxy = ips(opc)  

     Set objShell = WScript.CreateObject("WScript.Shell")  
     RegLocate = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer"
     objShell.RegWrite RegLocate,newProxy,"REG_SZ"
     RegLocate = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable"
     objShell.RegWrite RegLocate,"1","REG_DWORD"

End Sub

'________________________________________________________

Sub endProxyServer()
   
     Set objShell = WScript.CreateObject("WScript.Shell")  
     RegLocate = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer"
     objShell.RegWrite RegLocate,"0.0.0.0:80","REG_SZ"
     RegLocate = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable"
     objShell.RegWrite RegLocate,"0","REG_DWORD"

   WScript.Quit

End Sub

'______________________________________________________


