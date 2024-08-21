************************************************************************************************
# Deauther
## Acceso
+ Default red: pwned
+ PSK: deauther
+ URL: http://192.168.4.1/

## Links
+ https://blog.spacehuhn.com/deauther-web-interface
+ https://deauther.com/
+ https://github.com/spacehuhntech/esp8266_deauther

************************************************************************************************
# Ducky scripts

## Comando para añadir las instrucciones de Ducky Script
~~~bash
awk '{print "STRINGLN " $0 "\nDELAY 350"}' input_file.txt | tee output_file.txt  
~~~

## Dividir un archivo en varios
~~~bash
split -l 200000 -d --additional-suffix=.txt input_file.txt output_file
~~~

## Links
+ https://docs.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference
+ https://github.com/flipperdevices/flipperzero-firmware/blob/dev/documentation/file_formats/BadUsbScriptFormat.md
+ https://raw.githack.com/Zarcolio/flipperzero/main/BadUSB/Ducky%20Script%20creator/index.html
+ https://github.com/Zarcolio/flipperzero/tree/main/BadUSB

************************************************************************************************
# Flipper
## Comentarios
En caso de dispositivo no identificado, correr la app con `sudo`.

## Wifi Marauder
+ https://www.youtube.com/watch?v=zfd7wADSkD4

## Links
+ https://flipperzero.one/update
+ https://flipper-xtre.me/
+ https://github.com/Flipper-XFW/Xtreme-Firmware
+ https://docs.flipper.net/bad-usb

************************************************************************************************
# Malduino Elite
## Consideraciones importantes
El máximo número de caracteres por línea es 127
+ https://github.com/Seytonic/malduino/issues/21

## Scripts funcionales
+ 00 - 0000 [ok]
+ 01 - 0001 [ok]
+ 02 - 0010 [ok]
+ 03 - 0011 [ok]
+ 08 - 1000 [ok]
+ 09 - 1001 [ok]
+ 10 - 1010 [ok]
+ 11 - 1011 [ok]

## Todas las posibles combinaciones
+ 00 - 0000 => 0000 - 00 [ok]
+ 01 - 0001 => 0001 - 01 [ok]
+ 02 - 0010 => 0010 - 02 [ok]
+ 03 - 0011 => 0011 - 03 [ok]
+ 04 - 0100 => 0000 - 00 [no]
+ 05 - 0101 => 0001 - 01 [no]
+ 06 - 0110 => 0010 - 02 [no]
+ 07 - 0111 => 0011 - 03 [no]
+ 08 - 1000 => 1000 - 08 [ok]
+ 09 - 1001 => 1001 - 09 [ok]
+ 10 - 1010 => 1010 - 10 [ok]
+ 11 - 1011 => 1011 - 11 [ok]
+ 12 - 1100 => 1000 - 08 [no]
+ 13 - 1101 => 1001 - 09 [no]
+ 14 - 1110 => 1010 - 10 [no]
+ 15 - 1111 => 1011 - 11 [no]
## Setup
+ https://www.youtube.com/watch?v=cI3xlxGRGKU
+ https://www.arduino.cc/en/software
+ https://raw.githubusercontent.com/jLynx/MalDuino_Boards/master/IDE_Board_Manager/package_malduino_index.json
+ https://github.com/kripthor/malduino-elite

************************************************************************************************
# Raspberry Pi Zero - P4wnP1 A.L.O.A.
## Acceso
+ SSID: 💥🖥💥 Ⓟ➃ⓌⓃ🅟❶
+ PSK: MaMe82-P4wnP1
+ http://172.24.0.1:8000/#/generic

## Default passwords
+ root
+ toor

## SSH
+ ssh kali@172.24.0.1
+ toor

## Links
Repositorio:
+ https://github.com/RoganDawes/P4wnP1_aloa 
Imagen:
+ https://github.com/RoganDawes/P4wnP1_aloa/releases/tag/v0.1.1-beta
Instalación: 
+ https://rufus.ie/es/

## Comentarios
+ Falló al grabar la ISO en Linux

************************************************************************************************
# Ubertooth
## Links
+ https://github.com/greatscottgadgets/ubertooth
+ https://ubertooth.readthedocs.io/en/latest/build_guide.html
+ https://greatscottgadgets.com/ubertoothone/
+ https://www.theverge.com/23449206/ubertooth-one-bluetooth-ble-vulnerability-hacking-gadget
+ https://hackmd.io/@cs-feng-group/Sy2ALkWZK
+ https://wiki.elvis.science/index.php?title=Bluetooth_Sniffing_with_Ubertooth:_A_Step-by-step_guide

