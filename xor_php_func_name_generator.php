<?
if(sizeof($argv) < 2){
	echo "Usage: ".$argv[0]." FuncName  ( E.g: system )";
	die();
}else{
	while(True){
		$s1 = substr(str_shuffle(str_repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", strlen($argv[1]))), 0, strlen($argv[1]));
		$s2 = substr(str_shuffle(str_repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", strlen($argv[1]))), 0, strlen($argv[1]));
		$tmp = ($argv[1]^$s1^$s2);
		if(($tmp^$s1^$s2)==$argv[1]){
			if(ctype_print($tmp)){
				echo "\r[>] ".$tmp."^".$s1."^".$s2;
				if (!preg_match('/[^A-Za-z]/', $tmp)){
					echo "\r[+] ".$argv[1]." == (".$tmp."^".$s1."^".$s2.")\n";
					die();
				}
			}
		}
	}
}
