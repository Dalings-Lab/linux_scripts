#!/bin/bash

# Update server
apt update
apt -y upgrade

# Install
apt -y install strongswan
apt -y install libstrongswan-standard-plugins
apt -y install strongswan-pki
apt -y install zsh

# Iptables install
apt -y install debconf-utils
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt -y install iptables-persistent

# IP address
echo "Your IP address:"
read varip

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
tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
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

# Config for apple
echo "Input server name:"
read varname

varaconf='
#!/bin/zsh

CLIENT="me"
SERVER="'$varaconf'"
FQDN="'$varip'"
CA="ca"

# WiFi SSIDs that do not require automatic connection to VPN on network change
TRUSTED_SSIDS=("SSID1" "SSID2")

PAYLOADCERTIFICATEUUID=$( cat /proc/sys/kernel/random/uuid )
PKCS12PASSWORD=$( cat /proc/sys/kernel/random/uuid )

cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>${SERVER} VPN</string>
    <key>PayloadIdentifier</key>
    <string>${(j:.:)${(Oas:.:)FQDN}}</string>
    <key>PayloadUUID</key>
    <string>$( cat /proc/sys/kernel/random/uuid )</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key>
            <string>${SERVER} VPN</string>
            <key>PayloadDescription</key>
            <string>Configure VPN</string>
            <key>UserDefinedName</key>
            <string>${SERVER}</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>${FQDN}</string>
                <key>RemoteIdentifier</key>
                <string>${FQDN}</string>
                <key>LocalIdentifier</key>
                <string>${CLIENT}</string>
                <key>AuthenticationMethod</key>
                <string>Certificate</string>
                <key>PayloadCertificateUUID</key>
                <string>${PAYLOADCERTIFICATEUUID}</string>
                <key>CertificateType</key>
                <string>RSA</string>
                <key>ServerCertificateIssuerCommonName</key>
                <string>${FQDN}</string>
                <key>EnablePFS</key>
                <integer>1</integer>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-128-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>19</integer>
                </dict>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-128-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>19</integer>
                </dict>
                <key>OnDemandEnabled</key>
                <integer>1</integer>
                <key>OnDemandRules</key>
                <array>
                    <dict>
                        <key>InterfaceTypeMatch</key>
                        <string>WiFi</string>
                        <key>SSIDMatch</key>
                        <array>
`for x in ${TRUSTED_SSIDS}; echo "                            <string>$x</string>"`
                        </array>
                        <key>Action</key>
                        <string>Disconnect</string>
                    </dict>
                    <dict>
                        <key>InterfaceTypeMatch</key>
                        <string>Cellular</string>
                        <key>Action</key>
                        <string>Connect</string>
                    </dict>
                    <dict>
                        <key>Action</key>
                        <string>Connect</string>
                    </dict>
                </array>
            </dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.vpn.managed.${SERVER}</string>
            <key>PayloadUUID</key>
            <string>$( cat /proc/sys/kernel/random/uuid )</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        <dict>
            <key>PayloadDisplayName</key>
            <string>${CLIENT}.p12</string>
            <key>PayloadDescription</key>
            <string>Add PKCS#12 certificate</string>
            <key>PayloadCertificateFileName</key>
            <string>${CLIENT}.p12</string>
            <key>Password</key>
            <string>${PKCS12PASSWORD}</string>
            <key>PayloadContent</key>
            <data>
$( openssl pkcs12 -export -inkey /etc/ipsec.d/private/${CLIENT}.pem -in /etc/ipsec.d/certs/${CLIENT}.pem -name "${CLIENT}" -certfile /etc/ipsec.d/cacerts/${CA}.pem -password pass:${PKCS12PASSWORD} | base64 )
            </data>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.security.pkcs12.${CLIENT}</string>
            <key>PayloadUUID</key>
            <string>${PAYLOADCERTIFICATEUUID}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        <dict>
            <key>PayloadDisplayName</key>
            <string>${SERVER} CA</string>
            <key>PayloadDescription</key>
            <string>Add CA root certificate</string>
            <key>PayloadCertificateFileName</key>
            <string>ca.pem</string>
            <key>PayloadContent</key>
            <data>
$( cat /etc/ipsec.d/cacerts/${CA}.pem | base64 )
            </data>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.security.root.${SERVER}</string>
            <key>PayloadUUID</key>
            <string>$( cat /proc/sys/kernel/random/uuid )</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
</dict>
</plist>
EOF
'

echo "$varaconf" > mobileconfig.sh
chmod u+x mobileconfig.sh
./mobileconfig.sh > iphone.mobileconfig
