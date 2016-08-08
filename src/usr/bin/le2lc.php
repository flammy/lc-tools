#!/usr/bin/php
<?php
if(!isset($argv) || (count($argv) < 2) || array_key_exists('--help',array_flip($argv))){
	echo "Usage: ".basename(__FILE__)." [Options] \n";
	exit(1);
}

function parseConfFile($file){
	if(!file_exists($file)){
		return false;
	}
	$file_contents = file($file);
	if(!$file_contents){
		return false;
	}
	$config_array = array();
	foreach($file_contents as $line => $row){
		$row = trim(preg_replace("/#.*/","",$row));
		$key_values = explode("=",$row);
		if(isset($key_values[1])){
			$config_array[trim(array_shift($key_values))] =  trim(implode('',$key_values));
		}
	}
	return $config_array;
}


function query($query,$config){
	$return = array();
	if($config['db_driver'] == 'sqlite'){
		$db = new SQLite3( $config['db_name']);
		$query = $db->escapeString($query);
	}else{
		$db = mysqli($config['db_host'], $config['db_user'], $config['db_password'],$config['db_name']);
		$query = $db->real_escape_string($query);
	}
	if(!$db){
		return false;
	}
	$result = $db->query($query);
	if(!$result){
		return false;
	}
	while($row = $result->fetchArray()){
		$return[] = $row;
	}
	return $return;
}








?>

