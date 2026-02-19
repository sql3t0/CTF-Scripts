<#
Example Usage:

PS C:\Users\Myuser\Downloads> .\Cleaks-ValidateAdPasswords.ps1

cmdlet Cleaks-ValidateAdPasswords.ps1 na posição de comando 1 do pipeline
Forneça valores para os seguintes parâmetros:
Filename: cleaks_mycorp.csv
Domain: mydomain.com

user      Email                 Domain            ActiveOnAd SenhaValida UnlockedAccount
----      -----                 ------            ---------- ----------- ---------------
111111    111111@mydomain.com   mydomain.com       True       False      Sim
222222    222222@mydomain.com   mydomain.com       True       False      Sim
333333    333333@mydomain.com   mydomain.com       True       False      Sim
444444    444444@mydomain.com   mydomain.com       True       False      Sim
555555    555555@mydomain.com   mydomain.com       True        True      Não
666666    666666@mydomain.com   mydomain.com      False       False      Sim
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Filename,

    [Parameter(Mandatory=$true)]
    [string]$Domain
)

# Filename validation
if ((-not $Filename) -and (-not (Test-Path $Filename))) {
    Write-Error "File not Found: $Filename"
    exit
}

# Domain validation
if (-not $Domain) {
    Write-Error "Domain not Found: $Domain"
    exit
}

$CSVDATA = Import-Csv -Path $Filename

Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$validate = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
    [System.DirectoryServices.AccountManagement.ContextType]::Domain,
    $Domain
)

$results = foreach ($row in $CSVDATA) {

    $user = Get-ADUser -Filter "mail -eq '$($row.USUARIO)'" -Properties mail, Enabled

    if ($user) {

        $status = $validate.ValidateCredentials($user.SamAccountName, $row.SENHA)

        if (-not $status) {
            Unlock-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue
        }

        [PSCustomObject]@{
            user            = $user.SamAccountName
            Email           = $row.USUARIO
            Domain          = $Domain
            ActiveOnAd      = $user.Enabled
            SenhaValida     = $status
            UnlockedAccount = if (-not $status) { "Sim" } else { "Não" }
        }
    }
    else {
        [PSCustomObject]@{
            User            = "NTO FOUND"
            Email           = $row.USUARIO
            Domain          = $Domain
            ActiveOnAD      = "N/A"
            SenhaValida     = "N/A"
            UnlockedAccount = "N/A"
        }
    }
}

$results | Format-Table -AutoSize -Wrap -Force
