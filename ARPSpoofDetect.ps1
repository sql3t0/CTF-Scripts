$evtlog = "Application"
$source = "ARPMonitor"
$hostname = [System.Net.Dns]::GetHostName()
$timestamp = (get-date)
$DefaultGateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop
$arpCache = Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }

if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
    [System.Diagnostics.EventLog]::CreateEventSource($source, $evtlog)
}

function CreateParamEvent ($evtID, $param1, $param2, $param3) {
    $id = New-Object System.Diagnostics.EventInstance($evtID,1,2); #WARNING EVENT
    $evtObject = New-Object System.Diagnostics.EventLog;
    $evtObject.Log = $evtlog;
    $evtObject.Source = $source;
    $evtObject.WriteEvent($id, @($param1,$param2,$param3))
}

foreach ($entry in $arpCache) {
    foreach ($gw in $DefaultGateway) {
        $gmac = (Get-NetNeighbor -IPAddress $gw).LinkLayerAddress
        if ($gmac -ne '00-00-00-00-00-00'){
            if ($entry.LinkLayerAddress -eq $gmac -and $entry.IPAddress -ne $gw) {
                $utcDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                $attackerIp = $entry.IPAddress
                Write-Host "[$utcDate][$gmac|$gw] ARP spoofing detected! The MAC Address of the Gateway ($gw) is being modified to MAC ($gmac) of another device whit IP $attackerIp." -ForegroundColor Red
                CreateParamEvent 666 "UtcDateTime: $utcDate`nDefaultGatewayIP: $gw`nAttackerIP: $attackerIp`nAttackerMAC: $gmac`nMessage:`nARP spoofing detected!`nThe MAC Address of the Gateway ($gw) is being modified to MAC ($gmac) of another device whit IP $attackerIp." $hostname $timestamp
            }
        }
    }
}