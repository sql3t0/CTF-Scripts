<?php

if(!empty($argv[1])){
	$inputFile = $argv[1];
	$file  = file_get_contents($inputFile);		
	$lines = explode("\n", $file);
	$h = count($lines);
	$replaced = str_replace(", ", ",", $lines[0]) ;
	$rgbs = explode(" ", $replaced);
	$w =  count($rgbs);

	echo '<div style="width:'.$w.';height:'.$h.';">';
	foreach ($lines as $l){
		$replaced = str_replace(", ", ",", $l) ;
		$rgbs = explode(" ", $replaced);
		foreach ($rgbs as $c) {
			$color = "rgb".$c;
			echo '<div style="background-color:'.$color.';width:1px;height:1px;float:left;"></div>';
		}
	}
	echo '</div>';
}else{
	echo "Usage: php script.php file_name.txt > outFile.html \n";
}

?>
