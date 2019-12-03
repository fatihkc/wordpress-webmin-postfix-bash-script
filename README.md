# Wordpress, Webmin, Postfix, Let's Encrypt with Bash Script


This project developed for a customer to automating Wordpress installation. This script allow you to install and configure Wordpress, Webmin and Postfix alongside with Let's Encrypt. Note that this project developed for Centos 8.


# Technology Stack

  - MariaDB latest version (currently v10.4)
  - Nginx latest version (currently v1.16.1)
  - Php v7.3
  - Wordpress 5.0.2 (Can be change inside wp.conf)
  - Webmin v1.930

### Installation

While testing this script I used both vagrant and GCP instances and both worked well. You can choose your own provider.

Install the dependencies and devDependencies and start the server.

```sh
$ git clone https://github.com/fatihkc/wordpress-webmin-postfix-bash-script.git
$ cd wordpress-webmin-postfix-bash-script
$ vi wp.conf #change variables as you like.
$ vi wp.sh #change line 120 and 126 with your ip.
$ bash wp.sh
```
