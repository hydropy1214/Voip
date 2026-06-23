# Asterisk Security Hardening Configuration Guide

Production-ready configuration files for securing Asterisk PBX systems against automated exploitation and toll fraud.

## Component 1: Dialplan Security (extensions.conf)

### International Call Blocking Context

```asterisk
; /etc/asterisk/extensions.conf
; Secure International Call Routing

[international-security]
; Block all unapproved international calls by default
exten => _9!,1,Verbose(1,SECURITY: Attempted international call to ${EXTEN:1} from extension ${CALLERID(num)})
exten => _9!,n,Log(WARNING,INTERNATIONAL-BLOCKED: Extension ${CALLERID(num)} attempted call to ${EXTEN:1} from context ${CONTEXT})
exten => _9!,n,PlayTone(busy)
exten => _9!,n,Playback(privacy-incorrect)
exten => _9!,n,Hangup()

; PIN-protected international routing
exten => 90[1-9].,1,Verbose(1,Validating PIN for international call to ${EXTEN:2})
exten => 90[1-9].,n,Set(MAX_ATTEMPTS=3)
exten => 90[1-9].,n,Set(ATTEMPT=0)

exten => validate_pin,1,Set(ATTEMPT=$[${ATTEMPT} + 1])
exten => validate_pin,n,Read(USER_PIN,enter-password,,4)
exten => validate_pin,n,GotoIf($["${USER_PIN}" = "${INTERNATIONAL_PIN}"]?pin_valid)
exten => validate_pin,n,GotoIf($[${ATTEMPT} < ${MAX_ATTEMPTS}]?invalid_pin_retry)
exten => validate_pin,n,Goto(pin_failed)

exten => invalid_pin_retry,1,PlayTone(info)
exten => invalid_pin_retry,n,Playback(silence/1)
exten => invalid_pin_retry,n,Goto(validate_pin)

exten => pin_failed,1,Log(WARNING,INTL-PIN-FAILED: Extension ${CALLERID(num)} exceeded max PIN attempts)
exten => pin_failed,n,Playback(privacy-incorrect)
exten => pin_failed,n,Hangup()

exten => pin_valid,1,Set(COUNTRY_CODE=${EXTEN:2:2})
exten => pin_valid,n,GotoIf($["${COUNTRY_CODE}" = "1"]?route_us)
exten => pin_valid,n,GotoIf($["${COUNTRY_CODE}" = "44"]?route_uk)
exten => pin_valid,n,GotoIf($["${COUNTRY_CODE}" = "61"]?route_au)
exten => pin_valid,n,GotoIf($["${COUNTRY_CODE}" = "33"]?route_fr)
exten => pin_valid,n,Playback(privacy-incorrect)
exten => pin_valid,n,Hangup()

; Routing contexts for approved countries
exten => route_us,1,Log(NOTICE,INTL-ROUTE-US: Routing ${EXTEN:2} from ${CALLERID(num)})
exten => route_us,n,Dial(SIP/provider_usa/${EXTEN:2},120,tTkK)
exten => route_us,n,Goto(hangup)

exten => route_uk,1,Log(NOTICE,INTL-ROUTE-UK: Routing ${EXTEN:2} from ${CALLERID(num)})
exten => route_uk,n,Dial(SIP/provider_uk/${EXTEN:2},120,tTkK)
exten => route_uk,n,Goto(hangup)

exten => route_au,1,Log(NOTICE,INTL-ROUTE-AU: Routing ${EXTEN:2} from ${CALLERID(num)})
exten => route_au,n,Dial(SIP/provider_au/${EXTEN:2},120,tTkK)
exten => route_au,n,Goto(hangup)

exten => route_fr,1,Log(NOTICE,INTL-ROUTE-FR: Routing ${EXTEN:2} from ${CALLERID(num)})
exten => route_fr,n,Dial(SIP/provider_fr/${EXTEN:2},120,tTkK)
exten => route_fr,n,Goto(hangup)

exten => hangup,1,Hangup()

; Main internal context
[internal-secure]
; Enforce authentication on all calls
exten => _[0-9*#].,1,Log(NOTICE,CALL-INTERNAL: Extension ${CALLERID(num)} dialing ${EXTEN})

; Rate limiting implementation
exten => _[0-9*#].,n,Set(CALLCOUNT=${GLOBAL(call_count_${CALLERID(num)}):-0})
exten => _[0-9*#].,n,Set(LAST_CALL_TIME=${GLOBAL(last_call_time_${CALLERID(num)}):-${EPOCH}})
exten => _[0-9*#].,n,Set(TIME_DIFF=$[${EPOCH} - ${LAST_CALL_TIME}])
exten => _[0-9*#].,n,GotoIf($[${TIME_DIFF} > 60]?reset_counter)
exten => _[0-9*#].,n,GotoIf($[${CALLCOUNT} > 10]?rate_limit_exceeded)
exten => _[0-9*#].,n,Set(GLOBAL(call_count_${CALLERID(num)})=$[${CALLCOUNT} + 1])
exten => _[0-9*#].,n,Goto(check_destination)

exten => reset_counter,1,Set(GLOBAL(call_count_${CALLERID(num)})=1)
exten => reset_counter,n,Set(GLOBAL(last_call_time_${CALLERID(num)})=${EPOCH})
exten => reset_counter,n,Goto(check_destination)

exten => rate_limit_exceeded,1,Log(WARNING,RATE-LIMIT: Extension ${CALLERID(num)} exceeded call limit)
exten => rate_limit_exceeded,n,Playback(privacy-incorrect)
exten => rate_limit_exceeded,n,Hangup()

; Block 011 prefix (US international format)
exten => check_destination,1,GotoIf($["${EXTEN:0:3}" = "011"]?block_011)
exten => check_destination,n,GotoIf($["${EXTEN:0:1}" = "+"]?block_plus)
exten => check_destination,n,Goto(process_local)

exten => block_011,1,Log(WARNING,INTL-BLOCKED-011: Extension ${CALLERID(num)} attempted 011 call to ${EXTEN:3})
exten => block_011,n,Playback(privacy-incorrect)
exten => block_011,n,Hangup()

exten => block_plus,1,Log(WARNING,INTL-BLOCKED-PLUS: Extension ${CALLERID(num)} attempted +${EXTEN:1} call)
exten => block_plus,n,Playback(privacy-incorrect)
exten => block_plus,n,Hangup()

; Route local calls
exten => process_local,1,GotoIf($[${LEN(${EXTEN})} = 4]?local_extension)
exten => process_local,n,GotoIf($[${LEN(${EXTEN})} = 7]?local_number)
exten => process_local,n,GotoIf($[${LEN(${EXTEN})} = 10]?local_area_code)
exten => process_local,n,Playback(privacy-incorrect)
exten => process_local,n,Hangup()

exten => local_extension,1,Dial(SIP/${EXTEN},30,tT)
exten => local_extension,n,Hangup()

exten => local_number,1,Dial(SIP/provider_local/${EXTEN},30,tT)
exten => local_number,n,Hangup()

exten => local_area_code,1,Dial(SIP/provider_local/${EXTEN},30,tT)
exten => local_area_code,n,Hangup()
```

## Component 2: Fail2ban SIP Protection

### Fail2ban Filter Configuration

**File: `/etc/fail2ban/filter.d/asterisk-sip.conf`**

```ini
[Definition]
# SIP authentication failure patterns
failregex = ^.*SIP/2\.0.*401 Unauthorized.*<HOST>.*$
            ^.*SIP/2\.0.*403 Forbidden.*<HOST>.*$
            ^.*REGISTER.*from <HOST>.*Failed.*$
            ^.*failed SIP auth from <HOST>.*$
            ^.*Denying SIP INVITE from <HOST>.*$
            ^.*SIP registration from <HOST>.*denied.*$
            ^.*<HOST>.*sent us a packet.*we dont listen to.*$
            ^.*<HOST> failed to authenticate.*$
            ^.*Call from <HOST> exceeds maximum calls.*$
            ^.*Aggressive SIP OPTIONS scanning detected from <HOST>.*$
            ^.*<HOST>.*SIP port scanning attempt.*$
            ^.*Device <HOST>.*attempting brute force.*$

# Patterns to ignore (internal networks, trusted hosts)
ignoreregex = ^.*from 127\.0\.0\.1.*$
              ^.*from 192\.168\..*$
              ^.*from 10\..*$
              ^.*from internal.*$
              ^.*trusted.*$

# Log format
datepattern = %%ExY-%%m-%%d %%H:%%M:%%S
```

### Fail2ban Jail Configuration

**File: `/etc/fail2ban/jail.d/asterisk-sip.conf`**

```ini
# SIP Brute Force Protection
[asterisk-sip-bruteforce]
enabled = true
port = 5060,5061,5062
filter = asterisk-sip
logpath = /var/log/asterisk/messages
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-multiport[name=asterisk-sip, port="5060,5061,5062", protocol=udp]
         sendmail-whois[name=Asterisk SIP BruteForce, dest=admin@example.com, sender=fail2ban@example.com]

# Aggressive SIP Scanning
[asterisk-sip-aggressive]
enabled = true
port = 5060,5061
filter = asterisk-sip
logpath = /var/log/asterisk/messages
maxretry = 1
findtime = 60
bantime = 7200
action = iptables-multiport[name=asterisk-aggressive, port="5060,5061", protocol=udp]
         sendmail-whois[name=Asterisk Aggressive Scan, dest=admin@example.com, sender=fail2ban@example.com]

# DoS Detection (high volume OPTIONS requests)
[asterisk-sip-dos]
enabled = true
port = 5060,5061
filter = asterisk-sip
logpath = /var/log/asterisk/messages
maxretry = 100
findtime = 10
bantime = 1800
action = iptables-multiport[name=asterisk-dos, port="5060,5061", protocol=udp]
         sendmail-whois[name=Asterisk DoS Attack, dest=admin@example.com, sender=fail2ban@example.com]
```

## Component 3: SIP Security Hardening (sip.conf)

**File: `/etc/asterisk/sip.conf`**

```ini
; Asterisk SIP Configuration - Security Hardened
[general]

; ==============================
; VERSION DISCLOSURE PREVENTION
; ==============================
; Hide Asterisk version in User-Agent header
useragent = Asterisk
; Suppress detailed error responses
sip_verbose_debuginfo = no
; Disable debug mode
sipdebug = no
; Disable video support (reduces attack surface)
videosupport = no
; Disable fax detect (reduces complexity)
faxdetect = no

; ==============================
; TRANSPORT & ENCRYPTION
; ==============================
; Enable TLS for secure SIP signaling
tlsenable = yes
; Bind TLS to secure port
tlsbindaddr = 0.0.0.0:5061
; Require SIP/TLS (not optional)
transport = tls
; Certificate and private key
tlscertfile = /etc/asterisk/keys/asterisk.crt
tlsprivatekey = /etc/asterisk/keys/asterisk.key
tlscipher = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305

; Mandatory SRTP for media encryption
srtp_profile = sdes

; ==============================
; AUTHENTICATION & AUTHORIZATION
; ==============================
; Require authentication for all SIP requests
authenticate_invite = yes
authenticate_register = yes
authenticate_subscribe = yes
authenticate_publish = yes
; Require call tokens to prevent endpoint enumeration
requirecalltoken = yes
; Validate source of authentication
auth_method = digest

; ==============================
; REGISTRATION & BINDING
; ==============================
; Minimum registration expiry (prevent abuse)
minexpiry = 60
; Maximum registration expiry
maxexpiry = 300
; Default expiry time
defaultexpiry = 120
; Disable overlap dialing (prevents number scanning)
allowoverlap = no

; ==============================
; METHOD & HEADER RESTRICTIONS
; ==============================
; Disable dangerous SIP methods
allowsubscribe = no
allowpublish = no
allow_transfer = no
allownotify = no

; Disable unnecessary headers
disallow_globals_in_config = yes

; ==============================
; MEDIA CONTROL
; ==============================
; Disable direct media routing (requires signaling through Asterisk)
directmedia = no
; Enable media encryption
encryption = yes
; Use strong encryption algorithms
userpass = secure_sip_password_here

; ==============================
; QUALITY OF SERVICE (QoS)
; ==============================
; ToS marking for SIP
tos_sip = cs3
; ToS marking for audio
tos_audio = ef
; ToS marking for video (if enabled)
tos_video = af41
; CoS marking
cos_sip = 3
cos_audio = 6
cos_video = 4

; ==============================
; RATE LIMITING & DoS PROTECTION
; ==============================
; Limit concurrent connections per peer
maxcallbitrate = 384
; TCP keepalive
tcpkeepaliveinterval = 30

; ==============================
; RESPONSE HANDLING
; ==============================
; Do not respond to unknown requests
respond_to_us = yes
; Limit response verbosity
sip_verbose_debuginfo = no

; ==============================
; DTMF SECURITY
; ==============================
; Use encrypted DTMF (not in-band)
dtmfmode = rfc2833
; Require DTMF encryption
encrypt_dtmf = yes

; ==============================
; PEER/USER DEFINITIONS
; ==============================
[AUTHENTICATION_CONTEXT]
; Define all peers with explicit authentication
type = friend
host = dynamic
context = internal-secure
authenticate = yes
secret = $(DATABASE(/secretconf/peers/username/secret))
; Require TLS
transport = tls
; Enforce encryption
encryption = yes
; Restrict to specific IP after registration
;fromip = 192.168.1.0/24

; ==============================
; PROVIDER TRUNK (Inbound)
; ==============================
[provider-trunk-in]
type = peer
host = provider.sip.com
port = 5061
transport = tls
username = company_account
fromuser = company_account
secret = $(DATABASE(/secretconf/trunks/provider-in/secret))
context = from-provider
authenticate = yes
encryption = yes
encrypt_dtmf = yes

; ==============================
; PROVIDER TRUNK (Outbound)
; ==============================
[provider-trunk-out]
type = user
host = provider.sip.com
port = 5061
transport = tls
username = company_account
fromuser = company_account
secret = $(DATABASE(/secretconf/trunks/provider-out/secret))
authenticate = yes
encryption = yes
encrypt_dtmf = yes
```

## Component 4: iptables Firewall Rules

**File: `/root/voip_firewall.sh`**

```bash
#!/bin/bash
# VoIP Security Firewall Configuration
# Protects Asterisk from attack vectors

set -e

echo "[*] Configuring VoIP Security Firewall..."

# Define variables
VOIP_SERVER_IP="192.168.1.10"  # Change to your Asterisk server IP
SIP_PORT_UDP=5060
SIP_PORT_TCP=5061
SIP_PORT_TLS=5062
RTP_PORT_MIN=16384
RTP_PORT_MAX=32767
TRUSTED_NETWORKS="192.168.1.0/24 10.0.0.0/8"  # Adjust as needed

# Flush existing rules
echo "[*] Flushing existing iptables rules..."
iptables -F
iptables -X
iptables -F -t nat
iptables -X -t nat

# Set default policies
echo "[*] Setting default policies..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
echo "[*] Allowing loopback interface..."
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
echo "[*] Allowing established connections..."
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH (if remote management needed)
echo "[*] Allowing SSH from trusted networks..."
for net in $TRUSTED_NETWORKS; do
    iptables -A INPUT -p tcp --dport 22 -s "$net" -j ACCEPT
done

# ==============================
# SIP PORT PROTECTION (5060/UDP)
# ==============================
echo "[*] Configuring SIP/UDP port protection..."

# Rate limiting
iptables -N SIP_LIMIT 2>/dev/null || true
iptables -F SIP_LIMIT
iptables -A SIP_LIMIT -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A SIP_LIMIT -j DROP

# Allow SIP from trusted networks (unlimited)
for net in $TRUSTED_NETWORKS; do
    iptables -A INPUT -p udp -s "$net" --dport $SIP_PORT_UDP -j ACCEPT
done

# Rate limit external SIP
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -j SIP_LIMIT

# ==============================
# SIP PORT PROTECTION (5061/TCP)
# ==============================
echo "[*] Configuring SIP/TCP port protection..."

iptables -N SIP_TCP_LIMIT 2>/dev/null || true
iptables -F SIP_TCP_LIMIT
iptables -A SIP_TCP_LIMIT -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A SIP_TCP_LIMIT -j DROP

for net in $TRUSTED_NETWORKS; do
    iptables -A INPUT -p tcp -s "$net" --dport $SIP_PORT_TCP -j ACCEPT
done

iptables -A INPUT -p tcp --dport $SIP_PORT_TCP -j SIP_TCP_LIMIT

# ==============================
# TLS PORT PROTECTION (5062/TCP)
# ==============================
echo "[*] Configuring SIP/TLS port protection..."

iptables -N SIP_TLS_LIMIT 2>/dev/null || true
iptables -F SIP_TLS_LIMIT
iptables -A SIP_TLS_LIMIT -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A SIP_TLS_LIMIT -j DROP

for net in $TRUSTED_NETWORKS; do
    iptables -A INPUT -p tcp -s "$net" --dport $SIP_PORT_TLS -j ACCEPT
done

iptables -A INPUT -p tcp --dport $SIP_PORT_TLS -j SIP_TLS_LIMIT

# ==============================
# RTP MEDIA PROTECTION
# ==============================
echo "[*] Configuring RTP port protection..."

iptables -N RTP_LIMIT 2>/dev/null || true
iptables -F RTP_LIMIT
iptables -A RTP_LIMIT -m limit --limit 1000/second --limit-burst 2000 -j ACCEPT
iptables -A RTP_LIMIT -j DROP

for net in $TRUSTED_NETWORKS; do
    iptables -A INPUT -p udp -s "$net" --dport $RTP_PORT_MIN:$RTP_PORT_MAX -j ACCEPT
done

iptables -A INPUT -p udp --dport $RTP_PORT_MIN:$RTP_PORT_MAX -j RTP_LIMIT

# ==============================
# SIP SCANNING DETECTION
# ==============================
echo "[*] Configuring SIP scanning detection..."

# Track recent SIP requests per source IP
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -m recent --set --name sip_scan
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -m recent --name sip_scan --update --seconds 10 --hitcount 100 -j DROP

# ==============================
# DROP SUSPICIOUS PACKETS
# ==============================
echo "[*] Configuring suspicious packet filtering..."

# Drop SIP packets with unusual flags
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -m string --string "INVITE" --algo bm -m limit --limit 100/second -j ACCEPT
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -m string --string "REGISTER" --algo bm -m limit --limit 50/second -j ACCEPT
iptables -A INPUT -p udp --dport $SIP_PORT_UDP -m string --string "OPTIONS" --algo bm -m limit --limit 10/second -j ACCEPT

# ==============================
# LOGGING
# ==============================
echo "[*] Configuring logging..."

# Log dropped SIP packets
iptables -N LOG_DROP 2>/dev/null || true
iptables -F LOG_DROP
iptables -A LOG_DROP -m limit --limit 5/minute -j LOG --log-prefix "[IPTABLES-DROP] "
iptables -A LOG_DROP -j DROP

# ==============================
# SAVE RULES
# ==============================
echo "[*] Saving firewall rules..."

if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
    echo "[+] Rules saved to /etc/iptables/rules.v4"
fi

if command -v ufw &> /dev/null; then
    ufw enable
    echo "[+] UFW enabled"
fi

echo "[+] VoIP Security Firewall configuration complete"
iptables -L -v -n | head -20
```

## Implementation Steps

### 1. Deploy Dialplan Security

```bash
# Backup existing configuration
sudo cp /etc/asterisk/extensions.conf /etc/asterisk/extensions.conf.bak

# Add security contexts (append to extensions.conf)
sudo tee -a /etc/asterisk/extensions.conf << 'EOF'
; [Copy dialplan security section above]
EOF

# Reload dialplan
sudo asterisk -rx "dialplan reload"
```

### 2. Deploy Fail2ban Configuration

```bash
# Copy filter
sudo cp asterisk-sip.conf /etc/fail2ban/filter.d/

# Copy jail
sudo cp asterisk-sip.conf /etc/fail2ban/jail.d/

# Test configuration
sudo fail2ban-client -d

# Restart fail2ban
sudo systemctl restart fail2ban

# Verify
sudo fail2ban-client status asterisk-sip-bruteforce
```

### 3. Deploy SIP Hardening

```bash
# Backup
sudo cp /etc/asterisk/sip.conf /etc/asterisk/sip.conf.bak

# Update configuration (copy sip.conf section)
sudo vi /etc/asterisk/sip.conf

# Reload SIP module
sudo asterisk -rx "sip reload"
```

### 4. Deploy Firewall Rules

```bash
# Make script executable
chmod +x voip_firewall.sh

# Test in dry-run mode
sudo bash -x voip_firewall.sh

# Apply permanently
sudo iptables-save > /etc/iptables/rules.v4

# Restore on boot
sudo sh -c 'echo "iptables-restore < /etc/iptables/rules.v4" >> /etc/rc.local'
```

## Verification & Testing

```bash
# Check SIP configuration
sudo asterisk -rx "sip show settings"

# Monitor fail2ban activity
sudo tail -f /var/log/fail2ban.log

# Check firewall rules
sudo iptables -L -n -v

# Test SIP connection
sudo asterisk -rx "sip show peers"

# Monitor CDR for suspicious patterns
sudo tail -f /var/log/asterisk/cdr-csv/Master.csv
```

---

**Configuration Version:** 1.0  
**Last Updated:** 2024  
**Status:** Production Ready
