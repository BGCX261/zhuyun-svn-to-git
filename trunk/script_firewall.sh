#!/bin/bash
################################################
# Script Firewall for regulare host
#
# Description:
# - restrictived inbound + outbound
# - basic port forward (DNAT)
################################################
################################################
# CHANGELOG

# Jul 21, 2008  SM: * Initial Create
# Sep 11, 2008  SM: * Removed Maine holes
# Oct 23, 2008	SM: * With VV added more info
# Oct 23, 2008  VV: * Added iptables history + WebDAV / SSL +
# Nov 13, 2008  SM: * Changed Francisco IPs
# Nov 20, 2008	VV: * Cleaned unused rules + added LOGDROP chains + added prefix
#                     + OUTPUT policy
# Nov 24, 2008	VV: * Added output DNS access + zabbix agent + common prefix
# Nov 27, 2008	VV: * Log new connections + strict IP ranges
# Dec  3, 2008	VV: * Add test feature + change to a real script with options
#                     + NTP output
# Dec 12, 2008	VV: * Cleaning + full review
# Mar 02, 2009  VV: * add HTTP + SMTP output + correct Zabbix server IP
# Apr 24, 2009	VV: * update the script to support 2 interfaces + add IN/OUT if
# Jul 27, 2009	VV: * allow all traffic on lo interface + comment out first flag
#                     input rule (cf. code)
#                   * open output SSH backup port + HTTPS output
# Jul 27, 2009	VV: * make test mode safer (policy ACCEPT + remove final DROP)
#                     + repair HTTPS_IF
#        					  * ensure safe checks for 2 interfaces and banned networks
# Sep 10, 2009	VV: * use different log level (7 - debug) to avoid polluting dmesg
# Jan 05, 2010	VV: * add Xen Chain forward Accept + parameter + Debian / CentOS
#                     compliant
#                   * add %START_EXTRA and %END_EXTRA tags for mass update
#                   * merge port-forward functions
# Apr 01, 2010  CH: * Change last rule of OUTPUT chain to REJECT
# Jun 22, 2010  JS: * Add basic port forward (SNAT) function the configuration
#                     methods should be FORWARD_TYPE:SOURCE_IP:PORT:DEST_IP:PORT  
# Dec 27, 2011  AL: * Added colors and better error reporting
#                   * Removed useless SNAT/PNAT
#                   * Added TCP/UDP option for NAT
#                   * added bacdir1,bacsto1/2/3,ssh3 config
# Jan 10, 2012  AL: * Added support for nc_first_runscripts:
#                     keepalived
# Sep 14, 2012  AL: * Added rate limiting options
# Sep 18, 2012  AL: * Fixed NATing
# MAY 15, 2013  RW: * Add SSH Port for 40022
# MAY 27, 2013  RW: * Change port 25 via all device
################################################

version_num=20130515

########################################################
# Script settings
########################################################
IPT=/sbin/iptables
IPT_SAVE=/sbin/iptables-save
DATE=/bin/date
DATE_FORMAT="+%y%m%d_%H%M%S"
TC=/sbin/tc

# depending if this is CentOS / RH -- Debian
# Red-Hat - CentOS
if [ -f /etc/redhat-release ]; then
  IPT_SAVE_FILE=/etc/sysconfig/iptables
  IPT_HISTORY_FOLDER=/etc/sysconfig/iptables_history
# Debian - Ubuntu
elif [ -f /etc/debian_version ]; then
  IPT_SAVE_FILE=/etc/iptables.rules
  IPT_HISTORY_FOLDER=/var/lib/iptables
else 
  IPT_SAVE_FILE=
  IPT_HISTORY_FOLDER=
  echo -e "$RED ERROR: The OS has detected neither RedHat / CentOS / Debian $NO_COLOR" >&2
  echo -e "$RED ERROR: Enter manually the location of the Save / History files $NO_COLOR" >&2
  exit 1
fi

# define number of interfaces in use (1 or 2)
IF_COUNT=1

# define interfaces IP (with 32bit mask - xx.xx.xx.xx/32)
# need to define the MY_PUBLIC_IP -- for port forwarding mostly
MY_ETH0_IP=10.1.10.2
MY_ETH1_IP=
MY_PUBLIC_IP="$MY_ETH0_IP"

# define whether the server is a DomO (needs FORWARD ACCEPT)
# Change to YES if this is a DomO
IS_XEN_DOMO="NO"

########################################################
# Ports Definition
########################################################
HIGH_SOURCE_PORTS=1024:65535
HTTP_PORT=80
HTTPS_PORT=443
FTP_PORT=21
SSH_PORT=22
SSH_DEFAULT_PORT=40022
DNS_PORT=53
NTP_PORT=123
SMTP_PORT=25
POP3_PORT=110
LDAP_PORT=389
LDAPS_PORT=636
IMAP_PORT=143
IMAPS_PORT=993
SYSLOG_PORT=514
MYSQL_PORT=3306
MEMCACHED_PORT=11211
POSTGRESQL_PORT=5432
BACULA_DIR_PORT=9101
BACULA_SD_PORT=9103
BACULA_FD_PORT=9102
ZABBIX_AGENT_PORT=10050
SSH_BACKUP_PORT=40024
LDAP_SSH_PORT=60022
# define custom services ports below (HTTP - FTP - custom ports - etc.)
HTTPS_CUSTOM_PORT=

########################################################
# define the inbound / outbound interfaces of the common services
########################################################
SSH_IF_IN=" -i eth0 "
SSH_IF_OUT=" -o eth0 "
SYSLOG_IF_IN=" -i eth0 "
SYSLOG_IF_OUT=" -o eth0 "
DNS_IF_IN=" -i eth0 "
DNS_IF_OUT=" -o eth0 "
HTTP_IF_IN=" -i eth0 "
HTTP_IF_OUT=" -o eth0 "
HTTPS_IF_IN=" -i eth0 "
HTTPS_IF_OUT=" -o eth0 "
FTP_IF_IN=" -i eth0 "
FTP_IF_OUT=" -o eth0 "
NTP_IF_IN=" -i eth0 "
NTP_IF_OUT=" -o eth0 "
#SMTP_IF_IN=" -i eth0 "
#SMTP_IF_OUT=" -o eth0 "
MYSQL_IF_IN=" -i eth0 "
MYSQL_IF_OUT=" -o eth0 "
ZABBIX_IF_IN=" -i eth0 "
ZABBIX_IF_OUT=" -o eth0 "
SSH_BACKUP_IF_OUT=" -o eth0 "
BACULA_IF_IN="  "
BACULA_IF_OUT="  "


########################################################
# Location IPs
########################################################
LOCALHOST_IP=127.0.0.1/32

SRV_NC_SSH1_IP=123.103.98.67/32
SRV_NC_SSH2_IP=61.129.13.27/32
SRV_NC_SSH3_IP=180.150.140.52/32

ZABBIX_SERVER_IP=61.129.13.29/32
SYSLOG_SERVER_IP=61.129.13.23/32
BACKUP_SERVER_IP=61.129.13.23/32

SRV_NC_BACDIR1_IP=123.103.98.72/32
SRV_NC_BACSTO1_IP=123.103.98.72/32
SRV_NC_BACSTO2_IP=61.129.13.23/32
SRV_NC_BACSTO3_IP=180.150.140.54/32

SRV_NC_LDAP1_IP=61.129.13.24
SRV_NC_LDAP1_INT_IP=10.2.1.100
SRV_NC_LDAP2_IP=123.103.98.76

##### %START_EXTRA HOST definition
##### %END_EXTRA HOST definition

##### %START of nc_first_run.sh other ips 
KEEPALIVED_OTHER_IP=


########################################################
# Rate limiting options
########################################################
# TC_ENABLED: 0 = off, 1 = on
TC_ENABLED=0
TC_PORT=80
TC_INT=eth1
TC_MAX="9mbit"
TC_BURST="10mbit"


########################################################
# port forward - temp files
########################################################

TMP_IPT_PORT_FW1=/tmp/iptable_port_forward_tmp1
TMP_IPT_PORT_FW2=/tmp/iptable_port_forward_tmp2
TMP_IPT_PORT_FW3=/tmp/iptable_port_forward_tmp3
TMP_IPT_PORT_FW4=/tmp/iptable_port_forward_tmp4

########################################################
# log prefix
########################################################
COMMON_LOG_PREFIX="IPTFW-"
# illegal traffic log prefix
ILLEGAL_PACKET="$COMMON_LOG_PREFIX""bad-flag"
ILLEGAL_NETWORK="$COMMON_LOG_PREFIX""bad-priv-ip"
ILLEGAL_OUTPUT_SRC="$COMMON_LOG_PREFIX""bad-out-ipsrc"

# new connection logs - system defined
NEW_INBOUND="$COMMON_LOG_PREFIX""new-conn" # to be used seldomly
NEW_SSH_INBOUND="$COMMON_LOG_PREFIX""new-ssh-conn"

# define custom log prefix
NEW_HTTP_INBOUND="$COMMON_PREFIX""new-http-conn"

RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"
########################################################
# run checking - valid script + right user
########################################################
run_check() {
  # check for user ID - has to be root
  if [ $((UID)) != 0 ]; then
    echo -e "$RED ERROR: You need to run this script as ROOT user $NO_COLOR" >&2
    exit 2
  fi

  # check that IF_COUNT is set
  if [ -z "$IF_COUNT" ] || [ $(($IF_COUNT)) -lt 1 ]; then
    echo -e "$RED ERROR: You need to define the number of interface in use on the host and edit IF_COUNT $NO_COLOR" >&2
    exit 2
  fi

  # $MY_ETH0_IP is not defined, or empty
  if [ -z "$MY_ETH0_IP" ]; then
    echo -e "$RED ERROR: You need to configure the script and edit MY_ETH0_IP $NO_COLOR" >&2
    exit 2
  fi

  # $MY_ETH1_IP is not defined, or empty
  if [ $(($IF_COUNT)) -gt 1 ] && [ -z "$MY_ETH1_IP" ]; then
    echo -e "$RED ERROR: You need to configure the script and edit MY_ETH1_IP $NO_COLOR" >&2
    exit 2
  fi
}

########################################################
# Backup iptables rules
########################################################
backup_rules() {
  # Backup current iptables rules
  if [ ! -d $IPT_HISTORY_FOLDER ]; then
    echo "Creating $IPT_HISTORY_FOLDER to store previous iptables settings: "
    mkdir -p $IPT_HISTORY_FOLDER
    if [ $? -ne 0 ]; then
      echo -e "$RED ERROR: Error on creation of: $IPT_HISTORY_FOLDER $NO_COLOR" >&2
      exit 2
    fi
  fi

  # Save current iptables settings
  echo "Saving iptables rules: "
  IPT_BACKUP_FILE=$IPT_HISTORY_FOLDER/iptables.`$DATE "$DATE_FORMAT"`
  $IPT_SAVE > $IPT_BACKUP_FILE
  if [ $? -ne 0 ]; then
    echo -e "$RED ERROR: Error on saving backup rules in: $IPT_BACKUP_FILE $NO_COLOR" >&2
    exit 2
  else
    echo -e "$GREEN Iptables rules saved in $IPT_BACKUP_FILE $NO_COLOR"
  fi
}

test_state() {
  STATE=`iptables -nvL INPUT | head -n1 | grep DROP | wc -l`
  if [ $STATE -eq 1 ] ; then
    if [ "$test_flag" = 0 ] ; then
      echo -e "$RED  ERROR: You can need to test before using '-a'. Please run:"
      echo -e "       bash $0 -t $NO_COLOR"
      exit 1
    fi
  fi
}


########################################################
# Clean iptables and set new rules
########################################################
clean_iptables() {
  # Cleanup old rules 
  # At this time firewall is in a secure, closed state
  echo "Cleaning rules - setting DROP policies - flush rules - delete chains: "
  $IPT -P INPUT DROP
  $IPT -P OUTPUT DROP
  # FORWARD CHAIN policy depends on the Server type (defaults - Drop --- Xen - Accept)
  if [ "$IS_XEN_DOMO" == "YES" ]; then
    $IPT -P FORWARD ACCEPT
  else 
    $IPT -P FORWARD DROP
  fi

  $IPT --flush        # Flush all rules, but keep policies
  $IPT -t nat --flush	# Flush NAT table as well
  $IPT --delete-chain
  $IPT -t mangle -F
  $TC qdisc del dev eth1 root &> /dev/null
  echo -e "$GREEN Cleaning done. $NO_COLOR"

  if [ $((test_flag)) -eq 1 ]; then
    echo "Adding failsafe iptables rules for iptables testing: "
    $IPT -A INPUT -p tcp -m state --state NEW --dport $SSH_PORT -j ACCEPT
    $IPT -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    echo -e "$GREEN Failsafe rules added. $NO_COLOR"
  fi

}

inbound_rules() {
  # return value
  return_val=0 ; return_val=$((return_val+$?))

  #Main Firewall rules start ###########################
  # create a LOGDROP chain to allow DROP then LOG
  echo "Creating custom log chains: "
  $IPT -N LOGDROP_ILLEGAL_PACKET 
  $IPT -A LOGDROP_ILLEGAL_PACKET -j LOG -m limit --limit 120/minute --log-prefix "$ILLEGAL_PACKET " --log-level debug
  $IPT -A LOGDROP_ILLEGAL_PACKET -j DROP

  $IPT -N LOGDROP_ILLEGAL_NETWORK
  $IPT -A LOGDROP_ILLEGAL_NETWORK -j LOG -m limit --limit 120/minute --log-prefix "$ILLEGAL_NETWORK " --log-level debug
  $IPT -A LOGDROP_ILLEGAL_NETWORK -j DROP

  $IPT -N LOGDROP_ILLEGAL_OUTPUT_SRC
  $IPT -A LOGDROP_ILLEGAL_OUTPUT_SRC -j LOG -m limit --limit 120/minute --log-prefix "$ILLEGAL_OUTPUT_SRC " --log-level debug
  $IPT -A LOGDROP_ILLEGAL_OUTPUT_SRC -j DROP

  $IPT -N LOGACCEPT_NEW_SSH_CONN
  $IPT -A LOGACCEPT_NEW_SSH_CONN -j LOG -m limit --limit 120/minute --log-prefix "$NEW_SSH_INBOUND " --log-level debug
  $IPT -A LOGACCEPT_NEW_SSH_CONN -j ACCEPT
  echo -e "$GREEN Custom log chains created. $NO_COLOR"
 
  # For the following rules we log and drop illegal network traffic
  # can be set to a new log file by defining --log-level
  # First thing, drop illegal packets.
  echo "Dropping illegal INBOUND traffic - packets + networks: "
  # $IPT -A INPUT -p tcp ! --syn -m state --state NEW -j LOGDROP_ILLEGAL_PACKET # New not SYN
  $IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LOGDROP_ILLEGAL_PACKET
  $IPT -A INPUT -p tcp --tcp-flags ALL ALL -j LOGDROP_ILLEGAL_PACKET
  $IPT -A INPUT -p tcp --tcp-flags ALL NONE -j LOGDROP_ILLEGAL_PACKET  # NULL packets
  $IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOGDROP_ILLEGAL_PACKET
  $IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOGDROP_ILLEGAL_PACKET # XMAS
  $IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j LOGDROP_ILLEGAL_PACKET  # FIN packet
  $IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOGDROP_ILLEGAL_PACKET 

  ############################
  # Drop illegal network ----- WARNING ONLY USE THIS ON PUBLIC IP INTERFACES
  # WARNING:
  #   - using VPN you can see several type of private network belonging to other ranges than "yours"
  ############################

  [ ${MY_ETH0_IP:0:8} != "192.168." ] && $IPT -A INPUT -i eth0 -s 192.168.0.0/16 -j LOGDROP_ILLEGAL_NETWORK # private network class C
  if [ $(($IF_COUNT)) -gt 1 ]; then
    [ ${MY_ETH1_IP:0:8} != "192.168." ] && $IPT -A INPUT -i eth1 -s 192.168.0.0/16 -j LOGDROP_ILLEGAL_NETWORK # private network class C
  fi

  $IPT -A INPUT -i eth0 -s 172.16.0.0/12 -j LOGDROP_ILLEGAL_NETWORK # private network class B
  if [ $(($IF_COUNT)) -gt 1 ]; then
    $IPT -A INPUT -i eth1 -s 172.16.0.0/12 -j LOGDROP_ILLEGAL_NETWORK # private network class B
  fi

  [ ${MY_ETH0_IP:0:3} != "10." ] && $IPT -A INPUT -i eth0 -s 10.0.0.0/8 -j LOGDROP_ILLEGAL_NETWORK # private network class A
  if [ $(($IF_COUNT)) -gt 1 ]; then
    [ ${MY_ETH1_IP:0:3} != "10." ] && $IPT -A INPUT -i eth1 -s 10.0.0.0/8 -j LOGDROP_ILLEGAL_NETWORK # private network class A
  fi

  $IPT -A INPUT -s 169.254.0.0/16 -j LOGDROP_ILLEGAL_NETWORK # DHCP hosts that IP has not been properly set

  echo -e "$GREEN Illegal INBOUND traffic dropped. $NO_COLOR"

  #### HOLES ####
  echo -en "Creating rules for allowed INBOUND traffic: $RED\n"
  # Established - should be tightened to allowed IP later
  $IPT -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

  # Local traffic - allow all on lo interface
  $IPT -A INPUT -i lo -j ACCEPT

  ## ICMP / Ping - should be tightened to allowed IP later
  $IPT -A INPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  $IPT -A INPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  $IPT -A INPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  $IPT -A INPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  $IPT -A INPUT -p icmp -j DROP

  ###### DHCP Rules ######
  $IPT -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

  ###### SSH inbound -- only from the main interface - to be changed in the future if we want to access it only through the private IF
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH1_IP --sport $HIGH_SOURCE_PORTS --dport $SSH_PORT -j ACCEPT
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH2_IP --sport $HIGH_SOURCE_PORTS --dport $SSH_PORT -j ACCEPT
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH3_IP --sport $HIGH_SOURCE_PORTS --dport $SSH_PORT -j ACCEPT

  ###### SSH inbound -- can access for any.
  $IPT -A INPUT -p tcp -m state --state NEW -m tcp --sport $HIGH_SOURCE_PORTS --dport $SSH_DEFAULT_PORT -j ACCEPT

  ###### LDAP SSH inbound
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH1_IP --sport $HIGH_SOURCE_PORTS --dport $LDAP_SSH_PORT -j ACCEPT
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH2_IP --sport $HIGH_SOURCE_PORTS --dport $LDAP_SSH_PORT -j ACCEPT
  $IPT -A INPUT $SSH_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_SSH3_IP --sport $HIGH_SOURCE_PORTS --dport $LDAP_SSH_PORT -j ACCEPT

  ###### %START_EXTRA SSH inbound
  ###### %END_EXTRA SSH inbound

  ###### Zabbix agentd inbound - from the main IF only until further change
  $IPT -A INPUT $ZABBIX_IF_IN -p tcp -m state --state NEW -m tcp -s $ZABBIX_SERVER_IP --sport $HIGH_SOURCE_PORTS --dport $ZABBIX_AGENT_PORT -j ACCEPT

  ###### %START_EXTRA ZABBIX inbound
  ###### %END_EXTRA ZABBIX inbound

  ###### Other host specific services - to be defined below ####
  ###### HTTP inbound

  # BACULA INPUT
  $IPT -A INPUT $BACULA_IF_IN -p tcp -m state --state NEW -m tcp -s $SRV_NC_BACDIR1_IP --sport $HIGH_SOURCE_PORTS --dport $BACULA_FD_PORT -j ACCEPT

  ###### %START_EXTRA CUSTOM inbound
  # Start of nc_first_run.sh config
  # NC_FIRST_RUN_KEEPALIVED_INPUT
  # NC_FIRST_RUN_NGINX_INPUT
  ###### %END_EXTRA CUSTOM inbound

  echo -e "$GREEN INBOUND holes created. $NO_COLOR"
  
  # Dropping any further traffic
  if [ $((test_flag)) -eq 0 ]; then
    $IPT -A INPUT -j DROP
  fi
}

outbound_rules() {
  echo -en "Creating OUTBOUND rules: $RED\n"
  # Local traffic allowed accept al on lo interface
  $IPT -A OUTPUT -o lo -j ACCEPT

  # First, we only allow packets to be sent out if they are using the interface's IP address
  $IPT -A OUTPUT -o eth0 ! -s $MY_ETH0_IP -j LOGDROP_ILLEGAL_OUTPUT_SRC
  # we only add this rule if we have more than one interface defined
  if [ $((IF_COUNT)) -gt 1 ]; then
    $IPT -A OUTPUT -o eth1 ! -s $MY_ETH1_IP -j LOGDROP_ILLEGAL_OUTPUT_SRC
  fi

  # allow established connections
  $IPT -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

  # allow output ICMP traffic (ping - traceroute - etc.)
  $IPT -A OUTPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  $IPT -A OUTPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  $IPT -A OUTPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  $IPT -A OUTPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  $IPT -A OUTPUT -p icmp -j DROP

  ###### DHCP Rules ######
  $IPT -A OUTPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

  # until further notice all traffic is restriction is applied to the main interface
  # DNS - NTP - HTTP - SMTP - SYSLOG
  # allow DNS traffic 
  $IPT -A OUTPUT $DNS_IF_OUT -p udp -m state --state NEW --dport $DNS_PORT -j ACCEPT

  # allow NTP traffic 
  $IPT -A OUTPUT $NTP_IF_OUT -p udp -m state --state NEW --dport $NTP_PORT -j ACCEPT

  # allow FTP traffic -- for system update
  $IPT -A OUTPUT $FTP_IF_OUT -p tcp -m state --state NEW --dport $FTP_PORT -j ACCEPT

  # allow HTTP traffic -- for system update
  $IPT -A OUTPUT $HTTP_IF_OUT -p tcp -m state --state NEW --dport $HTTP_PORT -j ACCEPT

  # allow HTTPS traffic -- for system update
  $IPT -A OUTPUT $HTTPS_IF_OUT -p tcp -m state --state NEW --dport $HTTPS_PORT -j ACCEPT

  # allow SMTP traffic for emails
  $IPT -A OUTPUT -p tcp -m state --state NEW --dport $SMTP_PORT -j ACCEPT

  # allow SSH traffic for internal communications
  $IPT -A OUTPUT $SSH_IF_OUT -p tcp -m state --state NEW --dport $SSH_PORT -j ACCEPT

  # allow SYSLOG traffic for emails
  $IPT -A OUTPUT $SYSLOG_IF_OUT -p tcp -m state --state NEW -d $SYSLOG_SERVER_IP --dport $SYSLOG_PORT -j ACCEPT

  # allow remote backup via scp
  $IPT -A OUTPUT $SSH_BACKUP_IF_OUT -p tcp -m state --state NEW -d $BACKUP_SERVER_IP --dport $SSH_BACKUP_PORT -j ACCEPT

  # LDAP out
  $IPT -A OUTPUT -p tcp -m tcp -d $SRV_NC_LDAP1_IP --dport $LDAPS_PORT -m state --state NEW -j ACCEPT
  $IPT -A OUTPUT -p tcp -m tcp -d $SRV_NC_LDAP1_INT_IP --dport $LDAPS_PORT -m state --state NEW -j ACCEPT
  $IPT -A OUTPUT -p tcp -m tcp -d $SRV_NC_LDAP2_IP --dport $LDAPS_PORT -m state --state NEW -j ACCEPT

  # Bacula outbound rules
  $IPT -A OUTPUT $BACULA_IF_OUT -p tcp -m state --state NEW --dport $BACULA_SD_PORT -j ACCEPT

  ###### %START_EXTRA CUSTOM outbound
  # Start of nc_first_run.sh config
  # NC_FIRST_RUN_KEEPALIVED_OUTPUT

  ###### %END_EXTRA CUSTOM outbound

  if [ $((test_flag)) -eq 0 ]; then
    $IPT -A OUTPUT -j REJECT
  fi
  echo -e "$GREEN OUTBOUND rules created $NO_COLOR"
}


forward_rules() {
  echo "Creating forward rules: "


  echo -e "$GREEN forward rules created $NO_COLOR"
  return
}


tc_rules() {
  if [ $TC_ENABLED -eq 1 ] ; then
    echo -e "$GREEN Setting up traffic control: $NO_COLOR"
    ################################################
    # SANITY CHECK
    ################################################
    if [ ! -f $TC ];then
      echo "$RED ERROR: /sbin/tc missing. Exiting. $NO_COLOR"
    else
      $TC qdisc del dev $TC_INT root
      $TC qdisc add dev $TC_INT root handle 1:0 htb default 10
      $TC class add dev $TC_INT parent 1:0 classid 1:10 htb rate $TC_MAX ceil $TC_BURST prio 0
      $IPT -A OUTPUT -t mangle -p tcp --sport $TC_PORT -j MARK --set-mark 10
      $TC filter add dev $TC_INT parent 1:0 prio 0 protocol ip handle 10 fw flowid 1:10
    fi
  fi
}

########################################################
# Port forwarding
#   For example
#   You can add lines follow pf_add_to_port_fw_list.
#   Format just likes pf_add_to_port_fw_list "A:B:C:D"
#   A means source IP or subnet
#   B means hit port on the GW
#   C means dest IP of server inside GW
#   D means dest port 
########################################################

# function to check that the syntax of the port-forwarding is correct
#   return 0 if correct
#   return >0 if wrong
pf_validate_port_forward_syntax() {
  echo "Checking port forward syntax: "
  port_fw="$1"
  # if no parameters - return BLANK (not taken care of)
  if [ -z "$port_fw" ]; then
    return 1
  fi

  # perform integrity check in here
  port_fw_f1=$(echo $port_fw | cut -f1 -d: | sed -e 's/ //g')
  port_fw_f2=$(echo $port_fw | cut -f2 -d: | sed -e 's/ //g')
  port_fw_f3=$(echo $port_fw | cut -f3 -d: | sed -e 's/ //g')
  port_fw_f4=$(echo $port_fw | cut -f4 -d: | sed -e 's/ //g')
  port_fw_f5=$(echo $port_fw | cut -f5 -d: | sed -e 's/ //g')

  # validate none of the fields are empty
  if [ -z "$port_fw_f1" ] || [ -z "$port_fw_f2" ] || [ -z "$port_fw_f3" ] || [ -z "$port_fw_f4" ] || [ -z "$port_fw_f5" ]; then
	# if any is empty return BLANK (not taken care of)
    echo -e "$RED ERROR: Not enough parameters given pf_validate_port_forward_syntax() $NO_COLOR"
    return 1
  else
    # if all fields are correct return the port forward
    echo -e "$GREEN Checking port forward syntax finished $NO_COLOR"
    return 0
  fi
}

# function to append the port forwarding to the list of port forwarding
# and help maintenance
pf_add_to_port_fw_list() {
  new_port_fw="$1"

  # validate the port forward - exit if the return code is not 0
  pf_validate_port_forward_syntax "$new_port_fw"
  if [ $? -ne 0 ]; then
    return
  fi

  if [ -z "$PORT_FW_LIST" ]; then
    PORT_FW_LIST=$new_port_fw
  else
    PORT_FW_LIST="$PORT_FW_LIST $new_port_fw"
  fi
}

########################################################
# Port Forwarding section
########################################################
# create port forwarding list (temp file)
pf_create_port_fw_list() {
  proto_type=$1
  #source_ip=$2
  source_ip="0.0.0.0/0"
  hit_port=$3
  dest_ip=$4
  dest_port=$5

  echo "$IPT -t nat -A PREROUTING -p $proto_type -d $MY_PUBLIC_IP -m $proto_type --dport $hit_port -j DNAT --to-dest $dest_ip:$dest_port" >> $TMP_IPT_PORT_FW1
  echo "$IPT -t nat -A POSTROUTING -s $dest_ip -j MASQUERADE" >> $TMP_IPT_PORT_FW2
  echo "$IPT -t nat -A POSTROUTING -s $source_ip -j MASQUERADE" >> $TMP_IPT_PORT_FW2

  echo "$IPT -A FORWARD $FORWARD_IN_OUT -d $source_ip -j ACCEPT " >> $TMP_IPT_PORT_FW3
  echo "$IPT -A FORWARD $FORWARD_OUT_IN -s $source_ip -j ACCEPT" >> $TMP_IPT_PORT_FW4
}

pf_clean_temp_files() {
  # clear the tmp file
  > $TMP_IPT_PORT_FW1
  > $TMP_IPT_PORT_FW2
  > $TMP_IPT_PORT_FW3
  > $TMP_IPT_PORT_FW4
}

########################################################
# port forwarding rules
########################################################
pf_apply_port_forwarding_rules() {
  # open the function of forward
  echo 1 > /proc/sys/net/ipv4/ip_forward
  # You had better set "net.ipv4.ip_forward=1" in "/etc/sysctl.conf"
  # If the FW reboot,the value is always 1  

  # clean temp files
  pf_clean_temp_files

  # run port forwarding rules
  for PFW in $PORT_FW_LIST;
  do
      params=`echo $PFW | sed -e 's/:/ /g'`
      pf_create_port_fw_list $params;
  done
  echo -e "Applying port forward rules: $RED"
  # compute the iptable rules and remove the repetitive rules
  for command in "`sort $TMP_IPT_PORT_FW1 | uniq`"; do eval "$command"; done
  for command in "`sort $TMP_IPT_PORT_FW2 | uniq`"; do eval "$command"; done
  for command in "`sort $TMP_IPT_PORT_FW3 | uniq`"; do eval "$command"; done
  for command in "`sort $TMP_IPT_PORT_FW4 | uniq`"; do eval "$command"; done
  echo -e "$GREEN Applied port forward rules $NO_COLOR"

  # clean temp files to avoid leaving trace on the system
  pf_clean_temp_files
}

port_forward_rules() {
  PORT_FW_LIST=
  # add the port forwarding to the list to be applied
  #pf_add_to_port_fw_list "tcp:0.0.0.0/0:8080:10.3.1.32:80"
  #pf_add_to_port_fw_list "udp:0.0.0.0/0:8080:10.3.1.32:80"

  # apply the port forwarding
  pf_apply_port_forwarding_rules
}

save_rules() {
  echo "Saving rules: "
  $IPT_SAVE > "$IPT_SAVE_FILE"
  if [ $? -ne 0 ]; then
    echo -e "$RED ERROR: Error on saving backup rules in: $IPT_SAVE_FILE $NO_COLOR" >&2
    exit 2
  else
    echo "Iptables rules saved in: $IPT_SAVE_FILE : "
  fi
  echo -e "$GREEN Rules saved. $NO_COLOR"
}


############################################
# Script common functions
############################################
help() {
  print_version
  printf "Usage: %s: [-h] [-v] [-t] [-a] args" $(basename $0)
  printf "\n
  -h -- display help (this page)
  -v -- display version
  -t -- test rules but no DROP policy nor DROP all at the end of the chain
  -a -- apply all rules -- for production use\n\n"
}

# display version number
print_version() {
  printf "Version: %s\n" $version_num
}

# get options to play with and define the script behavior
get_options() {
  # -h -- display help
  # -v -- display version
  # -t -- test rules but no DROP policy nor DROP all at the end of the chain
  # -a -- apply all rules

  while getopts 'hvta' OPTION
  do
    case "$OPTION" in
      h)    help
		exit 0
		;;
      v)    print_version
		exit 0
		;;
      t)    test_flag=1
		;;
      a)    test_flag=0
		;;
      ?)    help >&2
		exit 2
		;;
    esac
    # if a parameter entered by the user is '-'
    if [ -z "$OPTION" ]; then
      echo -e "$RED ERROR: Invalid option entered $NO_COLOR" >&2
      help >&2
      exit 2
    fi
  done
}

print_banner_header() {
  echo "############################################"
  echo $(basename $0)
  print_version
  echo "############################################"
}

print_banner_footer() {
  echo "############################################"
}

#######################################
# Main function
#######################################
main() {
  backup_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables rules backup $NO_COLOR" >&2; exit 2; fi
  clean_iptables
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables cleanup $NO_COLOR" >&2; exit 2; fi
  inbound_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables inbound rules definition $NO_COLOR" >&2; exit 2; fi
  outbound_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables outbound rules definition $NO_COLOR" >&2; exit 2; fi
  forward_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables forward rules definition $NO_COLOR" >&2; exit 2; fi
  port_forward_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables port forward rules definition $NO_COLOR" >&2; exit 2; fi
  tc_rules
    if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during shaping traffic $NO_COLOR" >&2; exit 2; fi

  # only save the rules when not in testing phase
  if [ $((test_flag)) -eq 0 ]; then
    save_rules
      if [ $? -ne 0 ]; then echo -e "$RED ERROR: Error during iptables rules backup $NO_COLOR" >&2; exit 2; fi
  fi
}

#######################################
# Execution of the script
#######################################

# check for valid / tuned script
run_check

# check that at least one parameter has been added when lauching the script
if [ -z "$@" ]; then
  help >&2
  exit 2
fi

# get options
get_options "$@"
test_state

# run main function
print_banner_header
main
print_banner_footer
echo "Done. \o/"

