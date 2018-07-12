#!/bin/bash

print_help () {
  echo -e "./install.sh www_basedir user group"
  echo -e "\tbase_dir: The place where the web application will be put in"
  echo -e "\tuser:     User of the web application"
  echo -e "\tgroup:    Group of the web application"
}

# Ensure to be root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Ensure there are enought arguments
if [ "$#" -ne 3 ]; then
  print_help
  exit
fi

#enable ipforward
sysctl -w net.ipv4.ip_forward=1

# Ensure there are the prerequisites
for i in strongswan openssl openvpn bower apache2 php7.0 libapache2-mod-php7.0 php-zip php-mysql mysql-server nodejs unzip git wget sed npm curl; do
  which $i > /dev/null
  if [ "$?" -ne 0 ]; then
    echo "Miss $i"
    read -n1 -p " You miss something, do you want to install and setup all the necessary? [y,n]" doit
    if [ "$doit" == "y" ] 
    then
        apt-get -y install openssl strongswan openvpn apache2 php7.0 libapache2-mod-php7.0 php-zip php-mysql mysql-server nodejs unzip git wget sed npm curl
	npm install -g bower
	ln -s /usr/bin/nodejs /usr/bin/node
        break
    fi
  fi
done

www=$1
user=$2
group=$3

openvpn_admin="$www/openvpn-admin"

# Check the validity of the arguments
if [ ! -d "$www" ] ||  ! grep -q "$user" "/etc/passwd" || ! grep -q "$group" "/etc/group" ; then
  print_help
  exit
fi

base_path=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


printf "\n################## Server informations ##################\n"

read -p "Server Hostname/IP: " ip_server

read -p "OpenVPN protocol (tcp or udp) [tcp]: " openvpn_proto

if [[ -z $openvpn_proto ]]; then
  openvpn_proto="tcp"
fi

read -p "Port [443]: " server_port

if [[ -z $server_port ]]; then
  server_port="443"
fi

# Get root pass (to create the database and the user)
mysql_root_pass=""
status_code=1

while [ $status_code -ne 0 ]; do
  read -p "MySQL root password: " -s mysql_root_pass; echo
  echo "SHOW DATABASES" | mysql -u root --password="$mysql_root_pass" &> /dev/null
  status_code=$?
done

sql_result=$(echo "SHOW DATABASES" | mysql -u root --password="$mysql_root_pass" | grep -e "^openvpn-admin$")
# Check if the database doesn't already exist
if [ "$sql_result" != "" ]; then
  echo "The openvpn-admin database already exists."
  exit
fi


# Check if the user doesn't already exist
read -p "MySQL user name for OpenVPN-Admin (will be created): " mysql_user

echo "SHOW GRANTS FOR $mysql_user@localhost" | mysql -u root --password="$mysql_root_pass" &> /dev/null
if [ $? -eq 0 ]; then
  echo "The MySQL user already exists."
  exit
fi

read -p "MySQL user password for OpenVPN-Admin: " -s mysql_pass; echo

# TODO MySQL port & host ?


printf "\n################## Certificates informations ##################\n"

read -p "Key size (1024, 2048 or 4096) [2048]: " key_size

read -p "Root certificate expiration (in days) [3650]: " ca_expire

read -p "Certificate expiration (in days) [3650]: " cert_expire

read -p "Country Name (2 letter code) [US]: " cert_country

read -p "State or Province Name (full name) [California]: " cert_province

read -p "Locality Name (eg, city) [San Francisco]: " cert_city

read -p "Organization Name (eg, company) [Copyleft Certificate Co]: " cert_org

read -p "Organizational Unit Name (eg, section) [My Organizational Unit]: " cert_ou

read -p "Email Address [me@example.net]: " cert_email

read -p "Common Name (eg, your name or your server's hostname) [ChangeMe]: " key_cn


printf "\n################## Creating the certificates ##################\n"

EASYRSA_RELEASES=( $(
  curl -s https://api.github.com/repos/OpenVPN/easy-rsa/releases | \
  grep 'tag_name' | \
  grep -E '3(\.[0-9]+)+' | \
  awk '{ print $2 }' | \
  sed 's/[,|"|v]//g'
) )
EASYRSA_LATEST=${EASYRSA_RELEASES[0]}

# Get the rsa keys
wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_LATEST}/EasyRSA-${EASYRSA_LATEST}.tgz
tar -xaf EasyRSA-${EASYRSA_LATEST}.tgz
mv EasyRSA-${EASYRSA_LATEST} /etc/openvpn/easy-rsa
rm -r EasyRSA-${EASYRSA_LATEST}.tgz
cd /etc/openvpn/easy-rsa

if [[ ! -z $key_size ]]; then
  export EASYRSA_KEY_SIZE=$key_size
fi
if [[ ! -z $ca_expire ]]; then
  export EASYRSA_CA_EXPIRE=$ca_expire
fi
if [[ ! -z $cert_expire ]]; then
  export EASYRSA_CERT_EXPIRE=$cert_expire
fi
if [[ ! -z $cert_country ]]; then
  export EASYRSA_REQ_COUNTRY=$cert_country
fi
if [[ ! -z $cert_province ]]; then
  export EASYRSA_REQ_PROVINCE=$cert_province
fi
if [[ ! -z $cert_city ]]; then
  export EASYRSA_REQ_CITY=$cert_city
fi
if [[ ! -z $cert_org ]]; then
  export EASYRSA_REQ_ORG=$cert_org
fi
if [[ ! -z $cert_ou ]]; then
  export EASYRSA_REQ_OU=$cert_ou
fi
if [[ ! -z $cert_email ]]; then
  export EASYRSA_REQ_EMAIL=$cert_email
fi
if [[ ! -z $key_cn ]]; then
  export EASYRSA_REQ_CN=$key_cn
fi

# Init PKI dirs and build CA certs
./easyrsa init-pki
./easyrsa build-ca nopass
# Generate Diffie-Hellman parameters
./easyrsa gen-dh
# Genrate server keypair
./easyrsa build-server-full server nopass

# Generate shared-secret for TLS Authentication
openvpn --genkey --secret pki/ta.key


printf "\n################## Setup OpenVPN ##################\n"

# Copy certificates and the server configuration in the openvpn directory
cp /etc/openvpn/easy-rsa/pki/{ca.crt,ta.key,issued/server.crt,private/server.key,dh.pem} "/etc/openvpn/"
cp "$base_path/installation/server.conf" "/etc/openvpn/"
mkdir "/etc/openvpn/ccd"
sed -i "s/port 443/port $server_port/" "/etc/openvpn/server.conf"

if [ $openvpn_proto = "udp" ]; then
  sed -i "s/proto tcp/proto $openvpn_proto/" "/etc/openvpn/server.conf"
fi

nobody_group=$(id -ng nobody)
sed -i "s/group nogroup/group $nobody_group/" "/etc/openvpn/server.conf"

printf "\n################## Setup firewall ##################\n"

# Make ip forwading and make it persistent
echo 1 > "/proc/sys/net/ipv4/ip_forward"
echo "net.ipv4.ip_forward = 1" >> "/etc/sysctl.conf"

# Get primary NIC device name
primary_nic=`route | grep '^default' | grep -o '[^ ]*$'`

# Iptable rules
iptables -I FORWARD -i tun0 -j ACCEPT
iptables -I FORWARD -o tun0 -j ACCEPT
iptables -I OUTPUT -o tun0 -j ACCEPT

#iptables -A FORWARD -i tun0 -o $primary_nic -j ACCEPT
#iptables -t nat -A POSTROUTING -o $primary_nic -j MASQUERADE
#iptables -t nat -A POSTROUTING -s 11.54.192.0/18 -o $primary_nic -j MASQUERADE
#iptables -t nat -A POSTROUTING -s 11.54.192.2/18 -o $primary_nic -j MASQUERADE
iptables -t nat -A POSTROUTING -o $primary_nic -j MASQUERADE
iptables -A FORWARD -i $primary_nic -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i tun0 -o $primary_nic -j ACCEPT


printf "\n################## Setup MySQL database ##################\n"

echo "CREATE DATABASE \`openvpn-admin\`" | mysql -u root --password="$mysql_root_pass"
echo "CREATE USER $mysql_user@localhost IDENTIFIED BY '$mysql_pass'" | mysql -u root --password="$mysql_root_pass"
echo "GRANT ALL PRIVILEGES ON \`openvpn-admin\`.*  TO $mysql_user@localhost" | mysql -u root --password="$mysql_root_pass"
echo "FLUSH PRIVILEGES" | mysql -u root --password="$mysql_root_pass"


printf "\n################## Setup web application ##################\n"

# Copy bash scripts (which will insert row in MySQL)
cp -r "$base_path/installation/scripts" "/etc/openvpn/"
chmod +x "/etc/openvpn/scripts/"*

# Configure MySQL in openvpn scripts
sed -i "s/USER=''/USER='$mysql_user'/" "/etc/openvpn/scripts/config.sh"
sed -i "s/PASS=''/PASS='$mysql_pass'/" "/etc/openvpn/scripts/config.sh"

# Create the directory of the web application
mkdir "$openvpn_admin"
cp -r "$base_path/"{index.php,sql,bower.json,.bowerrc,js,include,css,installation/client-conf} "$openvpn_admin"

# New workspace
cd "$openvpn_admin"

# Replace config.php variables
sed -i "s/\$user = '';/\$user = '$mysql_user';/" "./include/config.php"
sed -i "s/\$pass = '';/\$pass = '$mysql_pass';/" "./include/config.php"

# Replace in the client configurations with the ip of the server and openvpn protocol
for file in "./client-conf/gnu-linux/client.conf" "./client-conf/osx-viscosity/client.conf" "./client-conf/windows/client.ovpn"; do
  sed -i "s/remote xxx\.xxx\.xxx\.xxx 443/remote $ip_server $server_port/" $file

  if [ $openvpn_proto = "udp" ]; then
    sed -i "s/proto tcp-client/proto udp/" $file
  fi
done

# Copy ta.key inside the client-conf directory
for directory in "./client-conf/gnu-linux/" "./client-conf/osx-viscosity/" "./client-conf/windows/"; do
  cp "/etc/openvpn/"{ca.crt,ta.key} $directory
done

# Install third parties
bower --allow-root install
chown -R "$user:$group" "$openvpn_admin"

printf "\033[1m\n#################################### Finish ####################################\n"

echo -e "# Congratulations, you have successfully setup OpenVPN-Admin! #\r"
echo -e "Please, finish the installation by configuring your web server (Apache, NGinx...)"
echo -e "and install the web application by visiting http://your-installation/index.php?installation\r"
echo  "Then, you will be able to run OpenVPN with systemctl start openvpn@server\r"
printf "\n################################################################################ \033[0m\n"

/etc/init.d/apache2 start

printf "\n################## Setup Strongswan ##################\n"

read -p "Public IP of your premise (Side A of the tunnel): " ex_A
read -p "CIDR internal addresses of your premise (10.0.0.0/24): " in_A
read -p "Public IP of the other premise (Side B of the tunnel): " ex_B
read -p "CIDR internal addresses of the other premise (10.2.0.0/24): " in_B
pskKey=$(printf '%s' $(openssl rand -base64 64))

echo "$ex_A $ex_B : PSK \"$pskKey\"" > /etc/ipsec.secrets

echo "# basic configuration" > /etc/ipsec.conf
echo "config setup" >> /etc/ipsec.conf
echo "        charondebug=\"all\"" >> /etc/ipsec.conf
echo "        uniqueids=yes" >> /etc/ipsec.conf
echo "        strictcrlpolicy=no" >> /etc/ipsec.conf

echo "# connection to B datacenter" >> /etc/ipsec.conf
echo "conn A-to-B" >> /etc/ipsec.conf
echo "  authby=secret" >> /etc/ipsec.conf
echo "  left=%defaultroute" >> /etc/ipsec.conf
echo "  leftid=$ex_A" >> /etc/ipsec.conf
echo "  leftsubnet=$in_A" >> /etc/ipsec.conf
echo "  right=$ex_B" >> /etc/ipsec.conf
echo "  rightsubnet=in_B" >> /etc/ipsec.conf
echo "  ike=aes256-sha2_256-modp1024!" >> /etc/ipsec.conf
echo "  esp=aes256-sha2_256!" >> /etc/ipsec.conf
echo "  keyingtries=0" >> /etc/ipsec.conf
echo "  ikelifetime=1h" >> /etc/ipsec.conf
echo "  lifetime=8h" >> /etc/ipsec.conf
echo "  dpddelay=30" >> /etc/ipsec.conf
echo "  dpdtimeout=120" >> /etc/ipsec.conf
echo "  dpdaction=restart" >> /etc/ipsec.conf
echo "  auto=start" >> /etc/ipsec.conf

iptables -t nat -A POSTROUTING -s $in_B -d $in_A -j MASQUERADE

echo "install strongswan"
echo "insert the following into /etc/ipsec.secrets of side B machine"
echo "$ex_B $ex_A : PSK \"$pskKey\"" 
echo "issue the following command to enable ipforward into side B machine: sysctl -w net.ipv4.ip_forward=1"
echo "issue the following command to instruct iptables: iptables -t nat -A POSTROUTING -s $in_A -d $in_B -j MASQUERADE"
echo "restart ipsec like this: ipsec restart"

