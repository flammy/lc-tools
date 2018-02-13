<?php

/**
 * Retrieve information on a single certificate $file
 *
 * @param string $file
 *
 * @return array
 */
function getCertificateDetails($file)
{
    $result = [];
    $result['serial'] = exec('cat ' . $file . ' | openssl x509 -noout -fingerprint');
    $result['name'] = exec('cat ' . $file . ' | openssl x509 -noout -subject');
    $result['issuer'] = exec('cat ' . $file . ' | openssl x509 -noout -issuer');
    $result['validfrom'] = exec('cat ' . $file . ' | openssl x509 -noout -startdate');
    $result['validto'] = exec('cat ' . $file . ' | openssl x509 -noout -enddate');
    $return = [];

    foreach ($result as $key => $value) {
        $tmp = explode('=', $value);
        $return[$key] = $tmp[max(array_keys($tmp))];
    }

    $return['crt'] = file_get_contents($file);
    $return['path'] = dirname($file);

    return $return;
}

/**
 * @param string $folder
 * @param array  $config
 *
 * @return array
 */
function getAllCertificateInfoByRecursiveDirScan($folder, $config = [])
{
    $return = $certificateDetails = [];
    $contents = scandir($folder);
    foreach ($contents as $content) {
        if ('.' === $content || '..' === $content) {
            continue;
        }

        if (is_dir($folder . DIRECTORY_SEPARATOR . $content)) {
            $readFiles = getAllCertificateInfoByRecursiveDirScan($folder . DIRECTORY_SEPARATOR . $content, $config);
            if (0 < count($readFiles)) {
                $return[$content] = $readFiles;
            }
        } else {
            if (isset($config['filenames']) && 0 < count($config['filenames'])) {
                if (!in_array($content, $config['filenames'])) {
                    continue;
                }
            }

            $type = array_search($content, $config['filenames']);

            switch ($type) {
                case 'cert':
                    $certificateDetails['cert'] = getCertificateDetails($folder . DIRECTORY_SEPARATOR . $content);
                    break;
                case 'privKey':
                    $certificateDetails['privkey'] = file_get_contents($folder . DIRECTORY_SEPARATOR . $content);
                    break;
                case 'chain':
                    $certificateDetails['chain'] = file_get_contents($folder . DIRECTORY_SEPARATOR . $content);
                    break;
                default:
            }

            $return = $certificateDetails;
        }
    }

    return $return;
}


/**
 * @param string $liveConfigDb
 * @param array  $certificates
 * @param array  $config
 */
function symlinkCertificates($liveConfigDb, $certificates, $config)
{
    $db = new SQLite3($liveConfigDb);
    $results = $db->query('SELECT * FROM sslcerts');

    echo 'checking for certificates without symlinks' . PHP_EOL;

    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        if (isset($certificates[$row['SSL_NAME']])) {
            if ('' ===  $row['SSL_FILENAME'] || null === $row['SSL_FILENAME']) {
                echo $row['SSL_NAME'] . ' has not a SSL_FILENAME linked in LiveConfig DB... skip!' . PHP_EOL;
                continue;
            }

            $liveConfigCert = $certificates[$row['SSL_NAME']];
            $oldCertName = '/etc/ssl/certs/' . $row['SSL_FILENAME'] . '.crt';

            if (!is_link($oldCertName)) {
                $newCertName = $liveConfigCert['cert']['path'] . DIRECTORY_SEPARATOR . $config['filenames']['cert'];
                if (file_exists($newCertName)) {
                    rename($oldCertName, $oldCertName . '.bak');
                    symlink($newCertName, $oldCertName);
                    echo 'Linking: ' . $oldCertName . " => " . $newCertName . PHP_EOL;
                }
            } else {
                echo $oldCertName . ' is already a symlink ' . PHP_EOL;
            }

            $oldPrivKeyName = '/etc/ssl/private/' . $row['SSL_FILENAME'] . '.key';
            if (!is_link($oldPrivKeyName)) {
                $newPrivKeyName = $liveConfigCert['cert']['path']
                    . DIRECTORY_SEPARATOR . $config['filenames']['privkey'];
                if (file_exists($newPrivKeyName)) {
                    rename($oldPrivKeyName, $oldPrivKeyName . '.bak');
                    symlink($newPrivKeyName, $oldPrivKeyName);
                    echo 'Linking: ' . $oldPrivKeyName . ' => ' . $newPrivKeyName . PHP_EOL;
                }
            } else {
                echo $oldPrivKeyName . ' is already a symlink ' . PHP_EOL;
            }

            $oldChainName = '/etc/ssl/certs/' . $row['SSL_FILENAME'] . '-ca.crt';

            if (!is_link($oldChainName)) {
                $newChainName = $liveConfigCert['cert']['path'] . DIRECTORY_SEPARATOR . $config['filenames']['chain'];

                if (file_exists($newChainName)) {
                    rename($oldChainName, $oldChainName . '.bak');
                    symlink($newChainName, $oldChainName);
                    echo 'Linking: ' . $oldChainName . ' => ' . $newChainName . PHP_EOL;
                }
            } else {
                echo $oldChainName . ' is already a symlink ' . PHP_EOL;
            }
        }
    }

}

/**
 * @param string $liveConfigDb
 * @param array $certificates
 *
 * @return bool whether or not certificates where renewed by certbot
 */
function checkExpire($liveConfigDb, $certificates)
{
    $TIME_30_DAYS = 30 * 24 * 60 * 60;
    $db = new SQLite3($liveConfigDb);
    $results = $db->query('SELECT * FROM sslcerts');
    $renewCerts = false;

    echo 'Scanning LiveConfig for known certificates, which are about to expire:' . PHP_EOL;

    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        if (isset($certificates[$row['SSL_NAME']])) {
            $liveConfigCert = $certificates[$row['SSL_NAME']];
            echo 'checking ' . $row['SSL_NAME'] . PHP_EOL;

            $validLetsEncrypt = strtotime($liveConfigCert['cert']['validto']);
            $validLiveConfig = strtotime($row['SSL_VALIDTO']);
            $renew = (time() + $TIME_30_DAYS);

            if ($validLetsEncrypt < $renew && $validLiveConfig < $renew) {
                echo 'Planning Renew: Cert is about to expire in < '
                    . (((time() - $renew) / 24 / 60 / 60) * -1)
                    . ' days'
                    . PHP_EOL;
                $renewCerts = true;
            } else {
                echo 'Cert is valid until: (Let\'s Encrypt: '
                    . date('d-m-y H:i:s', $validLetsEncrypt)
                    . ' | LiveConfig: '
                    . date('d-m-y H:i:s', $validLiveConfig) . ')'
                    . PHP_EOL;
            }
        }
    }

    if ($renewCerts) {
        exec('/root/certbot/certbot-auto renew', $output, $returnStatus);
        if ($returnStatus != 0) {
            echo 'Renew Failed:' . PHP_EOL;
            echo implode(PHP_EOL, $output);
        } else {
            echo 'Renew Succeeded' . PHP_EOL;
            echo implode(PHP_EOL, $output);

            return true;
        }
    }

    return false;
}

/**
 * @param string $liveConfigDb
 * @param array  $certificates
 */
function checkLiveconfig($liveConfigDb, $certificates)
{
    echo 'Creating backup of ' . $liveConfigDb . PHP_EOL;
    copy($liveConfigDb, $liveConfigDb . '.bak' . time()) || exit('Backup failed! Mission abort!');

    $db = new SQLite3($liveConfigDb);
    $results = $db->query('SELECT * FROM sslcerts');
    echo 'Scanning LiveConfig for known certificates that are not in sync with let\'s Encrypt:' . PHP_EOL;

    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        if (isset($certificates[$row['SSL_NAME']])) {
            $liveConfigCert = $certificates[$row['SSL_NAME']];

            echo 'checking ' . $row['SSL_NAME'] . PHP_EOL;

            $valid_le = strtotime($liveConfigCert['cert']['validto']);
            $valid_lc = strtotime($row['SSL_VALIDTO']);

            if ($valid_lc === $valid_le) {
                echo 'everything is in sync' . PHP_EOL;
            } elseif ($valid_lc < $valid_le) {
                echo 'LiveConfig certificate is outdated, importing from let\'s encrypt' . PHP_EOL;
                $stmt = $db->prepare('
                    UPDATE sslcerts
                    SET 
                    SSL_CRT=:SSL_CRT, 
                    SSL_CACHAIN=:SSL_CACHAIN, 
                    SSL_SERIAL=:SSL_SERIAL, 
                    SSL_VALIDFROM=:SSL_VALIDFROM, 
                    SSL_VALIDTO=:SSL_VALIDTO 
                    WHERE SSL_ID=:SSL_ID
                ');

                $validFrom = date('Y-m-d H:i:s', strtotime($liveConfigCert['cert']['validfrom']));
                $validTo = date('Y-m-d H:i:s', strtotime($liveConfigCert['cert']['validto']));

                $stmt->bindValue(':SSL_CRT', $liveConfigCert['cert']['crt'], SQLITE3_BLOB);
                $stmt->bindValue(':SSL_CACHAIN', $liveConfigCert['chain'], SQLITE3_BLOB);
                $stmt->bindValue(':SSL_SERIAL', $liveConfigCert['cert']['serial'], SQLITE3_BLOB);
                $stmt->bindValue(':SSL_VALIDFROM', $validFrom, SQLITE3_BLOB);
                $stmt->bindValue(':SSL_VALIDTO', $validTo, SQLITE3_BLOB);
                $stmt->bindValue(':SSL_ID', $row['SSL_ID'], SQLITE3_INTEGER);

                $stmt->execute();
            } else {
                echo 'LiveConfig certificate is newer than let\'s encrypt one, skipping.' . PHP_EOL;
            }
        }
    }
}

$liveConfigDb = '/var/lib/liveconfig/liveconfig.db';

$config = ['filenames' => ['cert' => 'cert.pem', 'chain' => 'chain.pem', 'privkey' => 'privkey.pem']];
$folder = '/etc/letsencrypt/live';
$certificates = getAllCertificateInfoByRecursiveDirScan($folder, $config);
symlinkCertificates($liveConfigDb, $certificates, $config);
checkLiveconfig($liveConfigDb, $certificates);
$result = checkExpire($liveConfigDb, $certificates);

if ($result) {
    echo 'Syncing Renewed Certificated with Liveconfig';
    $certificates = getAllCertificateInfoByRecursiveDirScan($folder, $config);
    checkLiveconfig($liveConfigDb, $certificates);
}

echo 'Restarting LiveConfig service' . PHP_EOL;
exec('/usr/sbin/service liveconfig restart');

echo 'Restarting apache2 service' . PHP_EOL;
exec('/usr/sbin/service apache2 restart');