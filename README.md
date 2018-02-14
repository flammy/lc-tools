# lc-tools
Tools for LiveConfig

Warning LiveConfig overwrites your certificate-files. This Script links the LiveConfig certificates with your Let's Encrypt certificates. 

To keep your LiveConfig entries up-to-date this script updates the entries in the LiveConfig database.

**Its current not possible to Update the privatekey because the private key is stored encrypted in the LiveConfig database.**

**If you run an update of your lets encrypt certificate certbot will create a new privatekey every time.**

**If you update your certificates with certbot, LiveConfig will overwrite your private key with your old private key.**

**This Problem is currently not solved!**

le2lc.php helps you sync your Let's Encrypt certificates with LiveConfig.

* scans your Let's Encrypt directory for certificates
* scans your LiveConfig database for certificates
* checks if there is a Let's Encrypt certificate for your LiveConfig certificate
* adds a symlink from the LiveConfig certificate file to the Let's Encrypt certificate file
* checks if one of the certificates is about to expire 
* updates the certificates with certbot
* backups the LiveConfig database
* updates the LiveConfig database with the new certificate details

## certbot 
At first you need a running certbot (`certbot/certbot-auto renew  --dry-run` runs without any errors)

I suggest the webroot method:
https://certbot.eff.org/docs/using.html#webroot

e.g.:

`certbot-auto certonly --webroot -w /var/www/example/htdocs/ -d www.example.com -d example.com `

If you made a certificate for multiple subdomains Let's Encrypt tries to find the same .well-known folder on all subdomains.

You can use your main domain as webroot and add symlinks to your subdomains, if they are in the same package.

`/var/www/example/htdocs/subdomain/.well-known => /var/www/example/htdocs/.well-known/ `

## Configuration (TBD)
TBD: There is a configfile in /etc/lc-tools/lc-tools.conf to configure it.

TBD: All configuration-parameters are also available as command line options, also there is a rudimentary --help option.

