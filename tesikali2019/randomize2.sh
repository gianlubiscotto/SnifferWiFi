while true; do
	ifconfig wlan0 down
	macchanger -r wlan0 | grep -E 'Current|New' >> macs.txt
	ifconfig wlan0 up
	iw wlan0 scan
	sleep 5
done
