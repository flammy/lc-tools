# lc-tools
Tools for liveconfig

Warning liveconfig overwrites your certificate-files. This Script links the Liveconfig certificates with your letsencrypt certificates. 

To keep your liveconfig entries up-to-date this script updates the entries in the liveconfig database.

**Its current not possible to Update the privatekey because the private key is stored encrypted in the liveconfig database.**

**If you run an update of your lets encrypt certificate certbot will create a new privatekey everytime. **

**If you update your certificates with certbot, liveconfig will overwrite your private key with your old private key.**

**This Problem is currently not solved!**

le2lc.php Helps you sync your letsencrypt certificates with liveconfig.

* scans your letsencrypt directetory for certificates
* scans your liveconfig database for certificates
* checks if there is a letsencrypt certificate for your liveconfig certificate
* adds a symlink from the liveconfig certificate file to the letsencrypt certificate file
* checks if one of the certificates is about to expire 
* updates the certificates with certbot 
* updates the liveconfig database with the new certificate details

## certbot 
At first you need a running certbot (`certbot/certbot-auto renew  --dry-run` runs without any errors)

I suggest the webroot method:
https://certbot.eff.org/docs/using.html#webroot

e.g.:

`certbot-auto certonly --webroot -w /var/www/example/htdocs/ -d www.example.com -d example.com `

If you made a certificate for multiple subdomains letsencrypt tries to find the same .well-known folder on all subdomains.

You can use your main domain as webroot and add symlinks to your subdomains, if they are in the same package.

`/var/www/example/htdocs/subdomain/.well-known => /var/www/example/htdocs/.well-known/ `

## Configuration
There is a configfile in /etc/lc-tools/lc-tools.conf to configure it.

All configuration-parameters are also available as comand line options, also there is a rudimentary --help option.

