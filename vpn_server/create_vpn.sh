#!/bin/bash

#Private

# Vars
echo "Input server name:"
read varname

echo "Your IP address:"
read varip

# Update server
apt update
apt -y upgrade

# Install
apt -y install \
strongswan \
libstrongswan-standard-plugins \
strongswan-pki \
wget \
zsh

# Iptables install
apt -y install debconf-utils
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt -y install iptables-persistent

# Remember dir
vardir=$(pwd)
echo "$vardir"

#1.0 Config for apple
wget https://raw.githubusercontent.com/Dalings-Lab/linux_scripts/main/vpn_server/mobileconfig.sh
sed -i '/AWS Frankfurt/s/AWS Frankfurt/'$varname'/g' mobileconfig.sh
sed -i '/YOUR_LIGHTSAIL_IP/s/YOUR_LIGHTSAIL_IP/'$varip'/g' mobileconfig.sh

# Create CA Certificate
cd /etc/ipsec.d
ipsec pki --gen --type rsa --size 4096 --outform pem > private/ca.pem
ipsec pki --self --ca --lifetime 3650 --in private/ca.pem \
--type rsa --digest sha256 \
--dn "CN=$varip" \
--outform pem > cacerts/ca.pem

# Create VPN server's certificate
ipsec pki --gen --type rsa --size 4096 --outform pem > private/debian.pem
ipsec pki --pub --in private/debian.pem --type rsa |
ipsec pki --issue --lifetime 3650 --digest sha256 \
--cacert cacerts/ca.pem --cakey private/ca.pem \
--dn "CN=$varip" \
--san $varip \
--flag serverAuth --outform pem > certs/debian.pem

# Certificate fo gadget
ipsec pki --gen --type rsa --size 4096 --outform pem > private/me.pem
ipsec pki --pub --in private/me.pem --type rsa |
ipsec pki --issue --lifetime 3650 --digest sha256 \
--cacert cacerts/ca.pem --cakey private/ca.pem \
--dn "CN=me" --san me \
--flag clientAuth \
--outform pem > certs/me.pem

# Clear
rm /etc/ipsec.d/private/ca.pem
> /etc/ipsec.conf

# Strongswan's config
varconf='
config setup
	uniqueids=never
	charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

conn %default
	keyexchange=ikev2
	ike=aes128gcm16-sha2_256-prfsha256-ecp256!
	esp=aes128gcm16-sha2_256-ecp256!
	fragmentation=yes
	rekey=no
	compress=yes
	dpdaction=clear
	left=%any
	leftauth=pubkey
	leftsourceip='$varip'
	leftid='$varip'
	leftcert=debian.pem
	leftsendcert=always
	leftsubnet=0.0.0.0/0
	right=%any
	rightauth=pubkey
	rightsourceip=10.10.10.0/24
	rightdns=8.8.8.8,8.8.4.4

conn ikev2-pubkey
	auto=add
'

echo "$varconf" > /etc/ipsec.config
echo ": RSA debian.pem" >> /etc/ipsec.secrets
ipsec restart

# Kernel network settings
sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.accept_redirects = 0/s/^#//g' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.send_redirects = 0/s/^#//g' /etc/sysctl.conf
echo "net.ipv4.ip_no_pmtu_disc = 1" >> /etc/sysctl.conf
sysctl -p

# Iptables setting
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -Z
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
netfilter-persistent save
netfilter-persistent reload

#1.1 Config for apple
sleep 5
zsh ${vardir}/mobileconfig.sh > ${vardir}/iphone.mobileconfig
sleep 5
rm mobileconfig.sh

reboot
exit