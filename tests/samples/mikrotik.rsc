# nov/06/2026 10:00:00 by RouterOS 7.14
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
add authentication-types=wpa2-psk mode=dynamic-keys name=prof1 \
    wpa2-pre-shared-key=LEAKwpa2 wpa-pre-shared-key="LEAK wpa"
/interface wireguard
add listen-port=13231 name=wg1 private-key="LEAKwgpriv="
/interface wireguard peers
add allowed-address=10.0.0.2/32 interface=wg1 public-key="PUBLICOK=" preshared-key="LEAKwgpsk="
/ppp secret
add name=vpnuser password=LEAKppp service=l2tp
/interface l2tp-server server
set enabled=yes ipsec-secret=LEAKl2tp use-ipsec=yes
/ip ipsec identity
add peer=p1 secret=LEAKipsec
/radius
add address=10.0.0.5 secret=LEAKrad service=login
/snmp community
set [ find default=yes ] name=LEAKcomm
add name=LEAKcomm2 authentication-password=LEAKsnmpa encryption-password=LEAKsnmpe
/user
add name=tech password=LEAKuser group=full
/tool e-mail
set password=LEAKmail server=smtp.example.com
/routing bgp connection
add name=peer1 tcp-md5-key=LEAKbgp
/interface wifi security
add name=sec1 passphrase=LEAKwifi
