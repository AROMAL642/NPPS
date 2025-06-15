nmap -sS 192.168.25.190 -p 1-100
nmap -sS 127.0.0.1 -p 1-100

//see alert on web
http://localhost:5000/
http://192.168.25.190:5000/


// to show list of ips blocked
sudo iptables -L -n --line-numbers

//unblock ip in iptables
sudo iptables -D INPUT -s 192.168.25.190 -j DROP

-------------------------------------------------------------------------------
//check DPI ( Run a Simple HTTP Server (Port 80 or 8080))

sudo python3 -m http.server 8080   //to make a demmy server
curl -X POST -d "login=admin&password=1234" http://127.0.0.1:8080


 //Start a Dummy FTP Server

 sudo systemctl start vsftpd
ftp 127.0.0.1

//Test Telnet
sudo systemctl start inetd
telnet 127.0.0.1






-------------features----------

✔Port scan Detects:---------------

SYN scans

NULL scans

FIN scans

XMAS scans


DPI for payload analysis:---------------------

HTTP keyword detection (login, password, /admin)

FTP plain text credentials

Telnet usage
