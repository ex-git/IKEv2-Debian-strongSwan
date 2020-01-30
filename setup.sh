#!/bin/bash -e

# tested in Debian 10

# == Then run this script
# chmod u+x setup.sh
# ./setup.sh

#sh -c 'printf "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/buster-backports.list'
apt-get -o Acquire::ForceIPv4=true update && apt-get -o Acquire::ForceIPv4=true upgrade -y
apt autoremove -y

#libcharon-extra-plugins is required, otherwise will receive "EAP-Identity request configured, but not supported" error
apt -o Acquire::ForceIPv4=true -t buster-backports install strongswan certbot iptables iptables-persistent libcharon-extra-plugins libstrongswan-extra-plugins -y

echo
echo "--- enable ipv4 forward and disable ipv6 ---"
echo

echo 'net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p

read -p "Hostname for VPN (default: ${DEFAULTVPNHOST}): " VPNHOST
VPNHOST=${VPNHOST:-$DEFAULTVPNHOST}
read -p "Email address for sysadmin (e.g. j.bloggs@example.com): " EMAILADDR
read -p "VPN username: " VPNUSERNAME
while true; do
read -p "VPN password (no quotes, please): " VPNPASSWORD
echo
read -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "$VPNPASSWORD" = "$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done
certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email $EMAILADDR -d $VPNHOST

ln -f -s /etc/letsencrypt/live/$VPNHOST/cert.pem /etc/ipsec.d/certs/cert.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/privkey.pem /etc/ipsec.d/private/privkey.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/chain.pem /etc/ipsec.d/cacerts/chain.pem

read -p "SSH log-in port (default: 22): " SSHPORT
SSHPORT=${SSHPORT:-22}
echo

VPNIPPOOL="10.10.10.0/24"

#ETH0ORSIMILAR = ${ip -o link show | awk '!/00:00:00:00:00:00/' | awk -F': ' '{print $2}'}
ETH0ORSIMILAR=$(ip route get 1.1.1.1 | awk -- '{printf $5}')

echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256gcm16-sha256-ecp521,aes256-sha256-ecp384!
  esp=aes256gcm16-sha256,aes256gcm16-ecp384!
  dpdaction=clear
  dpddelay=180s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=1.1.1.1,1.0.0.1
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"privkey.pem\"
${VPNUSERNAME} : EAP \""${VPNPASSWORD}"\"
" > /etc/ipsec.secrets

ipsec restart

echo
echo "--- Configuring firewall ---"
echo

# firewall
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --update --seconds 5 --hitcount 100 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport $SSHPORT -j ACCEPT

#Block SSH Brute Force Attacks with IPTables
iptables -I INPUT -p tcp --dport $SSHPORT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport $SSHPORT -i $ETH0ORSIMILAR -m state --state NEW -m recent  --update --seconds 60 --hitcount 4 -j DROP

#Open port for web http and https
#iptables -A INPUT -p tcp --dport 80 -j ACCEPT
#iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $ETH0ORSIMILAR -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j MASQUERADE


# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

#save current iptables rules
dpkg-reconfigure iptables-persistent
#iptables-save >/etc/iptables/rules.v4

#enable BBR
cat >> /etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

echo "Done"
