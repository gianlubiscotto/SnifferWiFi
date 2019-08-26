T1="wlan0mon"
sudo ifconfig wlan0 up
sudo airmon-ng start wlan0
T2=$(ifconfig | grep "wlan0mon" | cut -d ':' -f1)
#se la scheda era wlan0
if [$T2="wlan0mon"]
then
    echo "Wlan0mon activated"
else
    sudo ifconfig wlan1 up
    sudo airmon-ng start wlan1
fi
