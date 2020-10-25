if($args.count -eq 2){
	$DLLName = $args[0]
	$DLLbytes = [System.IO.File]::ReadAllBytes($DLLName)
	[System.Reflection.Assembly]::Load($DLLBytes)
	#lista todos os metodos na DLL
	#[Laricas.Encryption].GetMethods()
	$objeto = New-Object "Laricas.Encryption"
	$string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[1]))
	$enc = [system.Text.Encoding]::UTF8
	$data = $enc.GetBytes($string)
	$array = $objeto.crypt($data)
	$enc = [System.Text.Encoding]::ASCII
	$enc.GetString($array)
}else{
	echo "Usage : script.ps1 DLLName StringToDecode"
}
