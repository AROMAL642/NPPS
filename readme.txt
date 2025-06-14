nmap -sS 192.168.25.190 -p 1-100
nmap -sS 127.0.0.1 -p 1-100

//see alert on web
http://localhost:5000/
http://192.168.25.190:5000/


// to show list of ips blocked
sudo iptables -L -n --line-numbers

//unblock ip in iptables

sudo iptables -D INPUT -s 192.168.25.190 -j DROP




-------------features----------

✔ Detects:

SYN scans

NULL scans

FIN scans

XMAS scans
