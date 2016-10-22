<?php


	function certificate_details($file){
		$result = array();
		$result['serial'] = exec('cat '.$file.' | openssl x509 -noout -fingerprint');
		$result['name'] = exec('cat '.$file.' | openssl x509 -noout -subject');
		$result['issuer'] = exec('cat '.$file.' | openssl x509 -noout -issuer');
		$result['validfrom'] = exec('cat '.$file.' | openssl x509 -noout -startdate');
		$result['validto'] = exec('cat '.$file.' | openssl x509 -noout -enddate');
		$return = array();
		foreach($result as $k => $v){
			$tmp = explode('=',$v);
			$return[$k] = $tmp[max(array_keys($tmp))];
		}
		$return['crt'] = file_get_contents($file);
		$return['path'] = dirname($file);
		return $return;
	}


        function recursive_scandir($folder,$config = array()){
		$return = array();
                $contents = scandir($folder);
                foreach($contents as $content){
                        if($content == "." || $content == ".."){
                                continue;

                        }
                        if(is_dir($folder.DIRECTORY_SEPARATOR.$content)){
                                $read_files = recursive_scandir($folder.DIRECTORY_SEPARATOR.$content,$config);
                                if(count($read_files) > 0){
                                        $return[$content] = $read_files;
                                }
                        }else{
                                $fail = false;

                                if(isset($config['filenames']) && count($config['filenames'] > 0)){
                                        if(!in_array($content, $config['filenames'])){
                                                $fail = true;
                                        }
                                }


                                if($fail == false){
					$type = array_search($content,$config['filenames']);
					if($type == 'cert'){
						$certificate_details['cert'] = certificate_details($folder.DIRECTORY_SEPARATOR.$content);
					}
					if($type == 'privkey'){
						$certificate_details['privkey'] = file_get_contents($folder.DIRECTORY_SEPARATOR.$content);
					}
					if($type == 'chain'){
						$certificate_details['chain'] = file_get_contents($folder.DIRECTORY_SEPARATOR.$content);
					}

                                        $return = $certificate_details;
                                }
                        }
                }
                return $return;

        }


	function prepare_symlinks($certificates,$config){
		$db = new SQLite3('/var/lib/liveconfig/liveconfig.db');
                $results = $db->query("SELECT * FROM sslcerts");
		echo "checking for certificates without symlinks\n";
                while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
			if(isset($certificates[$row['SSL_NAME']])){
				$nolink = false;
				$old_cert_name = '/etc/ssl/certs/'.$row['SSL_FILENAME'].'.crt';
				if(!is_link($old_cert_name )){
					$nolink = true;
					$new_cert_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['cert'];
					if(file_exists($new_cert_name)){
						rename($old_cert_name,$old_cert_name.".bak");
						symlink($new_cert_name,$old_cert_name);
						echo "Linking: ".$old_cert_name." => ".$new_cert_name."\n";
					}
				}else{
					echo $old_cert_name." is allready a symlink \n";
				}
				$old_privkey_name = '/etc/ssl/private/'.$row['SSL_FILENAME'].'.key';
				if(!is_link($old_privkey_name)){
					$nolink = true;
					$new_privkey_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['privkey'];
					if(file_exists($new_privkey_name)){
						rename($old_privkey_name,$old_privkey_name.".bak");
						symlink($new_privkey_name,$old_privkey_name);
						echo "Linking: ".$old_privkey_name." => ".$new_privkey_name."\n";
					}
				}else{
					echo $old_privkey_name." is allready a symlink \n";
				}
				$old_chain_name = '/etc/ssl/certs/'.$row['SSL_FILENAME'].'-ca.crt';
				if(!is_link($old_chain_name)){
					$nolink = true;
					$new_chain_name =   $certificates[$row['SSL_NAME']]['cert']['path']."/".$config['filenames']['chain'];
					if(file_exists($new_chain_name)){
						rename($old_chain_name,$old_chain_name.".bak");
						symlink($new_chain_name,$old_chain_name);
						echo "Linking: ".$old_chain_name." => ".$new_chain_name."\n";
					}
				}else{
					echo $old_chain_name." is allready a symlink \n";
				}
			}
		}

	}


	function check_expire($certificates){
		$db = new SQLite3('/var/lib/liveconfig/liveconfig.db');
		$results = $db->query("SELECT * FROM sslcerts");
		$renew_certs = false;
		echo "Scanning liveconfig for Known certificates that are about to expire:\n";
		while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
			if(isset($certificates[$row['SSL_NAME']])){
				echo "checking ".$row['SSL_NAME']."\n";
				$valid_le = strtotime($certificates[$row['SSL_NAME']]['cert']['validto']);
				$valid_lc = strtotime($row['SSL_VALIDTO']);
				$renew = (time()+ ( 30 * 24 * 60 * 60));
				if($valid_le < $renew && $valid_lc < $renew){
					echo "Planning Renew: Cert is about to expire in < ".(((time()-$renew)/24/60/60)*-1)." days\n";
					$renew_certs =  true;
				}else{
					echo "Cert is valid til: ( le: ".date('d-m-y H:i:s',$valid_le)."| lc: ".date('d-m-y H:i:s',$valid_lc).")\n";
				}
			}
		}
		if($renew_certs){
			exec('/root/certbot/certbot-auto renew',$output,$ret_status);
			if($ret_status != 0){
				echo "Renew Failed:\n";
				echo implode("\n",$output);
			}else{
				echo "Renew Succeeded\n";
				echo implode("\n",$output);
				return true;
			}
		}
		return false;
	}


	function check_lc($certificates){
		$db = new SQLite3('/var/lib/liveconfig/liveconfig.db');
		$results = $db->query("SELECT * FROM sslcerts");
		echo "Scanning liveconfig for Known certificates that are not in sync with le:\n";
		while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
			if(isset($certificates[$row['SSL_NAME']])){
				echo "checking ".$row['SSL_NAME']."\n";
				$valid_le = strtotime($certificates[$row['SSL_NAME']]['cert']['validto']);
				$valid_lc = strtotime($row['SSL_VALIDTO']);
				if($valid_lc == $valid_le){
					echo "everything is in sync\n";
				}elseif($valid_lc < $valid_le){
					echo "lc is outdated, importing from le\n";
					$db->query("update SSLCERTS set SSL_CRT='".$certificates[$row['SSL_NAME']]['cert']['crt']."', SSL_CACHAIN='".$certificates[$row['SSL_NAME']]['chain']."', SSL_SERIAL='".$certificates[$row['SSL_NAME']]['cert']['serial']."', SSL_VALIDFROM='".date('Y-m-d H:i:s',strtotime($certificates[$row['SSL_NAME']]['cert']['validfrom']))."', SSL_VALIDTO='".date('Y-m-d H:i:s',strtotime($certificates[$row['SSL_NAME']]['cert']['validto']))."' where SSL_ID=".$row['SSL_ID']." ");
				}else{
					echo "lc certificate is newer than le, skipping.\n";
				}
			}
	 	}

	}


	
	$config = array('filenames' => array('cert' => 'cert.pem', 'chain' => 'chain.pem', 'privkey' => 'privkey.pem'));
	$folder = "/etc/letsencrypt/live";
	$certificates = recursive_scandir($folder,$config);
	prepare_symlinks($certificates,$config);
	$result = check_lc($certificates);
	$result = check_expire($certificates);
	if($result){
		echo "Syncing Renewed Certificated with Liveconfig";
		$certificates = recursive_scandir($folder,$config);
		$result = check_lc($certificates);
	}
	exec('/usr/sbin/service apache2 restart');
?>
