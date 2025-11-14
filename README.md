# Personal-Firewall
Simple user-space firewall using NFQUEUE and scapy.


Setup (Linux):

 . sudo apt install python3-pip
  
 . pip install netfilterqueue scapy
  
 . sudo iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 1
  
 . sudo iptables -I INPUT  -p tcp -j NFQUEUE --queue-num 1
  
 . sudo python3 personal_firewall.py

Edit BLOCKED_IPS and BLOCKED_TCP_PORTS in the script to change rules.
