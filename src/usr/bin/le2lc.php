#!/usr/bin/php
<?php
if(!isset($argv) || array_key_exists('--help',array_flip($argv))){
	echo "Usage: ".basename(__FILE__)." [Options] \n";
	echo "Options: --verbose	| -v 		verbose output\n";
	echo "         --test		| -t 		test-mode (no changes where written)\n";
	echo "         --help		| -h 		display this help\n";
	exit(1);
}

$loglevel = 0;

$dryrun = false;
foreach($argv as $k => $v){
	switch($v){
		case "-v":
		case "--verbose":
			$loglevel = 99;
			unset($argv[$k]);
		break;
		case "-t":
		case "--test":
			$dryrun = true;
			unset($argv[$k]);
		break;
	}
}

$le2lc = new le2lc($loglevel,$dryrun);


$local_config_file ="";

if(!$local_config = $le2lc->parseConfFile("/etc/lc-tools/lc-tools.conf")){
	$local_config = array();
	// $local_config['le_certpath'] = "/etc/letsencrypt/live";
	// $local_config['lc_config_file'] = ""M
	// 
}
$local_config['cert_config'] = array('filenames' => array('cert' => 'cert.pem', 'chain' => 'chain.pem', 'privkey' => 'privkey.pem'));
$local_config = $le2lc->parseArgv($argv,$local_config);

if(!$lc_config = $le2lc->parseConfFile($local_config['lc_config_file'])){
	$le2lc->log("Failed to parse lc-config-file");
	exit(1);
}

$certificates = $le2lc->recursive_scandir($local_config['le_certpath'],$local_config['cert_config']);
$new_links = $le2lc->prepare_symlinks($certificates,$local_config['cert_config'],$lc_config);
$symlinks_changed = $le2lc->check_lc($certificates,$lc_config);
$expired_certificates = $le2lc->check_expire($certificates,$lc_config);

if($expired_certificates){
	$renew = false;
	exec($local_config['certbot_path'].' renew',$output,$ret_status);
	if($ret_status != 0){
		$le2lc->log("Renew Failed");
		$le2lc->log(implode("\n",$output));
	}else{
		$renew = true;
		$le2lc->log("Renew Failed");
		$le2lc->log(implode("\n",$output));
	}
}

if($expired_certificates && $renew){
	$le2lc->log("Syncing Renewed Certificated with Liveconfig");
	$certificates = $le2lc->recursive_scandir($local_config['le_certpath'],$cert_config);
	$result = $le2lc->check_lc($certificates,$lc_config);
	exec($local_config['post_update_hook']);
}




class le2lc{
	private $loglevel;
	private $dryrun;



	public function __construct($loglevel = 0, $dryrun = false){
		$this->loglevel = $loglevel;
		$this->dryrun = $dryrun;
		if($this->dryrun){
			$this->log("Test-Mode activated");
		}
		if($this->loglevel > 0){
			$this->log("Verbose logging activated: (verbosity: ".$this->loglevel." )");
		}
	}


	
	
	public function log($message,$loglevel=0){
		if($loglevel <= $this->loglevel){
			echo $message."\n";
		}
	}
	
	
	public function backupConfigFile($file){
		$backupfile = $file.".bak";
		if(!file_exists($backupfile)){
			rename($file, $backupfile);
			return true;
		}
		$i = 1;
		while($i< 20){
			$backupfile = $file.".bak".$i;
			if(!file_exists($backupfile)){
				rename($file, $backupfile);
				return true;
			}
			$i++;
		}
	}


	public function parseConfFile($file){
		if(!file_exists($file)){
			$this->log("Configfile does not exist: ".$file." ");
			return false;
		}
		$file_contents = file($file);
		if(!$file_contents){
			$this->log("Configfile is not readable: ".$file." ");
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
		$this->log("Configfile parsed: ".$file." ",2);
		return $config_array;
	}

	public function parseArgv($argv,$local_config = array()){
		foreach($argv as $k => $v){
			// check if the current entry is a key or a switch
			if(preg_match("/^-.*/", $v) == 1){
				if(isset($argv[$k+1]) && preg_match("/^-.*/", $argv[$k+1]) == 1){
					// next entry begins with -- (is not a value: current entry is a switch)
					$local_config[str_replace("-", "", $v)] == true;
				}else{
					// next entry is a value for the current entry
					$local_config[str_replace("-", "", $v)] == $argv[$k+1];
				}
			}
		}
		return $local_config;
	}

	
	function query($query,$lc_config){
		$return = array();
		if($lc_config['db_driver'] == 'sqlite'){
			$db = new SQLite3( $lc_config['db_name']);
			$query = $db->escapeString($query);
		}else{
			$db = mysqli($lc_config['db_host'], $lc_config['db_user'], $lc_config['db_password'],$lc_config['db_name']);
			$query = $db->real_escape_string($query);
		}
		if(!$db){
			$this->log("Could not connect to database: ".$lc_config['db_name']." ");
			return false;
		}
		$result = $db->query($query);
		if(!$result){
			$this->log("Query failed '".$query."'");
			return false;
		}
		while($row = $result->fetchArray()){
			$return[] = $row;
		}
		$this->log("Query successfull '".$query."'",2);
		return $return;
	}
	
	function certificate_details($file,$type){
		if(!file_exists($file)){
			$this->log("Certificate file does not exist '".$file."'");
			return false;
		}
		$return = array();
		$this->log("Parsing certificate file '".$file."' as ".$type." ",2);
		switch($type){
			case "cert":
				$result = array();
				$result['serial'] = exec('cat '.$file.' | openssl x509 -noout -fingerprint');
				$result['name'] = exec('cat '.$file.' | openssl x509 -noout -subject');
				$result['issuer'] = exec('cat '.$file.' | openssl x509 -noout -issuer');
				$result['validfrom'] = exec('cat '.$file.' | openssl x509 -noout -startdate');
				$result['validto'] = exec('cat '.$file.' | openssl x509 -noout -enddate');
				foreach($result as $k => $v){
					$tmp = explode('=',$v);
					$return[$k] = $tmp[max(array_keys($tmp))];
				}
				$return['crt'] = file_get_contents($file);
				$return['path'] = dirname($file);
			break;
			case "privkey":
				$return = file_get_contents($file);
			break;
			case "chain":
				$return = file_get_contents($file);
			break;
			default:
				return false;
		}
		return $return;
	}
	
	function recursive_scandir($folder,$cert_config){
		if(!is_dir($folder)){
			$this->log("Folder does not exist'".$folder."");
			return false;
		}
		$return = array();
		$contents = scandir($folder);
		$this->log("Scanning folder '".$folder."'",2);
		foreach($contents as $content){
			if($content == "." || $content == ".."){
				continue;
			}
			if(is_dir($folder.DIRECTORY_SEPARATOR.$content)){
				$read_files = $this->recursive_scandir($folder.DIRECTORY_SEPARATOR.$content,$cert_config);
				if(count($read_files) > 0){
					$return[$content] = $read_files;
				}
			}else{
				$fail = false;
				if(isset($cert_config['filenames']) && count($cert_config['filenames'] > 0)){
					if(!in_array($content, $cert_config['filenames'])){
						$fail = true;
					}
				}
				if($fail == false){
					$type = array_search($content,$cert_config['filenames']);
					$return[$type] = $this->certificate_details($folder.DIRECTORY_SEPARATOR.$content,$type);
				}
			}
		}
		return $return;
	}
	
	
	
	function prepare_symlinks($certificates,$cert_config,$lc_config){
		$query ="SELECT * FROM sslcerts where ssl_issuer=\"Let's Encrypt Authority X3\"";
		$results = $this->query($query,$lc_config);
		$nolink = false;
		foreach ($results as $row) {
			if(isset($certificates[$row['SSL_NAME']])){
				$old_cert_name = '/etc/ssl/certs/'.$row['SSL_FILENAME'].'.crt';
				if(!is_link($old_cert_name )){
					$nolink = true;
					$new_cert_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['cert'];
					if(file_exists($new_cert_name)){
						if($this->dryrun == false){
							$this->backupConfigFile($old_cert_name);
						    symlink($new_cert_name,$old_cert_name);
						}
						$this->log("Linking: ".$old_cert_name." => ".$new_cert_name);
					}
				}else{
					$this->log($old_cert_name." is allready a symlink");
				}
				$old_privkey_name = '/etc/ssl/private/'.$row['SSL_FILENAME'].'.key';
				if(!is_link($old_privkey_name)){
					$nolink = true;
					$new_privkey_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['privkey'];
					if(file_exists($new_privkey_name)){
						if($this->dryrun == false){
							$this->backupConfigFile($old_privkey_name);
						    symlink($new_privkey_name,$old_privkey_name);
						}
						$this->log("Linking: ".$old_privkey_name." => ".$new_privkey_name);
					}
				}else{
					$this->log($old_privkey_name." is allready a symlink");
				}
				$old_chain_name = '/etc/ssl/certs/'.$row['SSL_FILENAME'].'-ca.crt';
				if(!is_link($old_chain_name)){
					$nolink = true;
					$new_chain_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['chain'];
					if(file_exists($new_chain_name)){
						if($this->dryrun == false){
							$this->backupConfigFile($old_chain_name);
						    symlink($new_chain_name,$old_chain_name);
                                                }
						$this->log("Linking: ".$old_chain_name." => ".$new_chain_name);
					}
				}else{
					$this->log($old_chain_name." is allready a symlink");
				}
			}
		}
		return $nolink;
	}



	function check_expire($certificates,$lc_config){
		$query ="SELECT * FROM sslcerts where ssl_issuer=\"Let's Encrypt Authority X3\n"";
		$results = $this->query($query,$lc_config);
		$renew_certs = false;
		$this->log("Scanning liveconfig for Known certificates that are about to expire");
		foreach ($results as $row) {
			if(isset($certificates[$row['SSL_NAME']])){
				$this->log("checking ".$row['SSL_NAME']);
				$valid_le = strtotime($certificates[$row['SSL_NAME']]['cert']['validto']);
				$valid_lc = strtotime($row['SSL_VALIDTO']);
				$renew = (time()+ ( 30 * 24 * 60 * 60));
				if($valid_le < $renew && $valid_lc < $renew){
					$this->log("Planning Renew: Cert is about to expire in < ".(((time()-$renew)/24/60/60)*-1)." days");
					$renew_certs =  true;
				}else{
					$this->log("Cert is valid til: ( le: ".date('d-m-y H:i:s',$valid_le)."| lc: ".date('d-m-y H:i:s',$valid_lc));
				}
			}
		}
		return $renew_certs;
	}


	function check_lc($certificates,$lc_config){
		$query ="SELECT * FROM sslcerts";
		$results = $this->query($query,$lc_config);
		$this->log("Scanning liveconfig for Known certificates that are not in sync with le");
		foreach ($results as $row) {
			if(isset($certificates[$row['SSL_NAME']])){
				$this->log("checking ".$row['SSL_NAME']);
				$valid_le = strtotime($certificates[$row['SSL_NAME']]['cert']['validto']);
				$valid_lc = strtotime($row['SSL_VALIDTO']);
				if($valid_lc == $valid_le){
					$this->log("everything is in sync");
				}elseif($valid_lc < $valid_le){
					$this->log("lc is outdated, importing from le");
				        if($this->dryrun == false){
					    $query ="update SSLCERTS set SSL_CRT='".$certificates[$row['SSL_NAME']]['cert']['crt']."', SSL_CACHAIN='".$certificates[$row['SSL_NAME']]['chain']."', SSL_SERIAL='".$certificates[$row['SSL_NAME']]['cert']['serial']."', SSL_VALIDFROM='".date('Y-m-d H:i:s',strtotime($certificates[$row['SSL_NAME']]['cert']['validfrom']))."', SSL_VALIDTO='".date('Y-m-d H:i:s',strtotime($certificates[$row['SSL_NAME']]['cert']['validto']))."' where SSL_ID=".$row['SSL_ID'];
					    $results = $this->query($query,$lc_config);
                                        }
				}else{
					$this->log("lc certificate is newer than le, skipping");
				}
			}
	 	}
	}

}
?>
