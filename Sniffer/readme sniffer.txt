PREREQUISITI:

eseguire per installare le librerie:
sudo apt-get install scapy && curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && sudo python get-pip.py && sudo pip install netaddr && sudo pip install requests && sudo apt-get install aircrack-ng && sudo apt-get install python-netifaces && sudo pip install pympler && sudo pip install mysql-connector	


monitor mode:
sudo ifconfig wlan1 up
(sudo airmon-ng check kill)
sudo airmon-ng start wlan1

per vedere se effettivamente una scheda è andata in monitor mode:
iwconfig
per farla tornare in managed mode:
sudo airmon-ng stop wlan1mon

avviare lo script:
sudo python snifferWiFi.py

per modificare azioni all'avvio del raspberry:
crontab -e 
e aggiungere come nuova linea:
@reboot <linea di comando>

collegamento tramite ssh:
raspi-config e abilitare ssh
da windows utilizzare putty
scabio file sftp:
WinSCP

usr-password raspberry: pi - raspberry 
usr-password raspberry raspi.img: pi - raspberrypi

collegamento reverse ssh tunnel con remot3.it:
sudo apt-get update
sudo apt-get install weavedconnectd
sudo weavedinstaller
-accesso con credenziali remot3.it
-nome del dispositivo
-abilitare servizio ssh
-da remot3.it cliccare sul dispositivo cliccare sul servizio ssh appena creato e copiare indirizzo-porta in un tool ssh



note:
nello script nel chiamare la funzione sniff, al parametro iface viene passata l'interfaccia con il nome più lungo (visto che quella in monitor mode si chiamerà "wlan?mon"
Nel crontab il raspberry si riavvia ogni X minuti con sudo shutdown -r +X
Nel crontab viene eseguita la routine per mettere in monitor sia wlan0 che wlan1. La routine è uno script bash chiamato monitor-routine.sh

Per ristabilire la connessione ethernet: sudo systemctl start dhcpcd