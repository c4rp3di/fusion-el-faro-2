# El Faro 2.1 · edición forense

Sin compilar. Revisión estática hecha; con espejos en Python se comprobaron los lectores de `ip neigh`, del escaneo Wi-Fi,
de `/proc/net/tcp` (direcciones IPv4/IPv6 en hexadecimal), de `appops`, de `getprop`, de `device_policy`, de `cmd wifi status`
y la construcción y lectura de consultas DNS. Es mucho código nuevo con APIs de Android: es normal que haga falta alguna
corrección tras compilar. Pásame el log.

Dependencias nuevas (las mismas versiones que Vigía, ya compiladas allí): libadb-android 1.0.1, sun-security-android 1.1 y
conscrypt-android 2.5.2, desde JitPack con filtro (`settings.gradle`).

## Novedades de la 2.1
- **Nombres de equipos**: toca un equipo > «Renombrar…». El nombre y la marca de «conocido» se guardan cifrados (por MAC; sin MAC, por IP).
  Un equipo nombrado o conocido deja de contar como «sin identificar» y de avisarse como «NUEVO». También en Bluetooth.
- **Paneles con detalle y acciones**: toca un hallazgo (detalle, qué hacer, atajos a los ajustes de Android o al panel del router, copiar y
  compartir), una sección (texto completo), la puntuación (cómo se calcula), «Tu red» o un equipo (renombrar, marcar como conocido, abrir su
  panel web, volver a escanear sus puertos, copiar IP/MAC, compartir ficha).
- **Bluetooth** (pantalla aparte, análisis puntual de unos 20 s): dispositivos BLE y clásicos con fabricante, clase y cercanía; posibles
  rastreadores (Apple «Buscar», Samsung SmartTag, Tile); si el teléfono es visible para todos; dispositivos emparejados; evidencia firmada.
- **IPv6**: ping a ff02::1 para ver equipos que solo hablan IPv6 (con ADB, su MAC y qué routers se anuncian: detecta anuncios de router
  falsos y un «router IPv6» distinto del IPv4); dirección IPv6 pública del teléfono (exposición sin NAT).
- **WS-Discovery** (UDP 3702): cámaras ONVIF, impresoras y equipos Windows dicen lo que son; mejora la clasificación.
- **NAT-PMP** (UDP 5351) y **versión del DNS del router** (`version.bind`, la anuncian dnsmasq y BIND).
- **Versiones conocidas**: compara los banners (SSH, FTP, HTTP, UPnP, DNS) con un conjunto pequeño y revisado a mano: vsftpd 2.3.4, ProFTPD
  1.3.3c, Apache 2.4.49/2.4.50, OpenSSL con Heartbleed, libupnp < 1.6.18, MiniUPnPd < 1.4, dnsmasq < 2.83 (DNSpooq), OpenSSH, Dropbear,
  SSH 1, IIS, Apache 2.0/2.2 sin soporte. NO es una base de datos de CVE.

## Tres botones
- **Solo router y red**: lo de antes + UPnP avanzado, DHCP, Wi-Fi, DNS, TLS, ruta y comparación con la visita anterior.
- **Análisis completo**: lo anterior + dispositivos (ahora con fabricante por MAC si hay ADB, y certificado de los equipos con HTTPS).
- **Análisis forense total**: lo anterior + revisión del teléfono + modo avanzado (ADB, si está conectado) + indicadores (IOC)
  + historial encadenado + paquete de evidencia firmado.

## Qué añade
Red (no necesita ADB; las pruebas con internet se pueden desactivar con la casilla):
- **UPnP avanzado**: IP externa del router y lista de reenvíos de puertos abiertos hacia internet (solo acciones «Get», solo al router).
- **DNS**: respuestas falsas (dirección privada para una web pública), interceptación del DNS (consulta a una IP inexistente que no debería
  contestar) y secuestro de NXDOMAIN.
- **HTTPS**: certificados de cuatro webs conocidas con la validación normal de Android; detecta fallos y cadenas que pasan por una CA
  instalada por el usuario. No se envían datos.
- **Ruta**: primer salto (debe ser el router), doble NAT y CGNAT.
- **DHCP**: servidor DHCP distinto del router. **Certificados de equipos**: caducados o débiles (solo se lee el certificado).
- **Cambios desde la última visita** (cifrado con Keystore): MAC del router, DNS, puertos nuevos del router, reenvíos UPnP nuevos.

Teléfono (modo forense, no necesita ADB): bloqueo de pantalla, proxy, DNS privado, VPN, parche de seguridad, CA instaladas por el usuario,
apps con accesibilidad / administrador / lector de notificaciones / teclado, apps instaladas fuera de una tienda, gestores de root.

Modo avanzado (ADB en este mismo teléfono, solo lectura; se empareja desde «Modo avanzado (ADB)»):
- **Tabla ARP con MAC** y fabricante (tabla OUI parcial): detecta ARP spoofing (la MAC del router en otras IP) y MAC aleatoria.
- **Wi-Fi sin ubicación**: cifrado real, BSSID, banda, y **gemelo malvado** (mismo nombre con cifrado distinto o abierto); redes abiertas guardadas.
- **Conexiones del teléfono** (`/proc/net`): quién habla con quién (por app) y qué apps aceptan conexiones desde la red.
- **Sistema**: root, bootloader desbloqueado, compilación de depuración, ADB por TCP, proxy global, verificación de apps, propietario del
  dispositivo/perfil (MDM o software espía), APK sueltos en el almacenamiento.
- **Apps con accesos especiales en detalle**: permisos sensibles concedidos, fecha de instalación y **último uso de cámara, micrófono,
  ubicación, SMS y contactos** (appops).

Evidencia:
- **Paquete firmado** (JSON, firma ECDSA con clave del Keystore): informe, equipos, secciones y las salidas crudas de cada comprobación,
  cada una con su SHA-256. «Verificar un paquete de evidencia» comprueba firma, hashes y si procede de este teléfono.
- **Historial encadenado**: cada análisis forense enlaza con el anterior por hash; si se toca el historial, la cadena se rompe.
- **Indicadores (IOC)**: importa tu lista (STIX2 o un indicador por línea: IP, dominios, paquetes). El Faro NO trae listas propias.
  Se cruzan con conexiones del teléfono, apps instaladas, DNS, IP pública y equipos de la red.

## Decisiones de seguridad y ética (cambios respecto a la 1.0)
- Sigue sin probar contraseñas ni atacar. Todo es lectura; ADB solo lee y solo en este teléfono. Nunca se conecta al ADB de otros equipos.
- **Ya no es la única conexión a internet el portal cautivo**: con la casilla activada también se contacta con google.com, wikipedia.org,
  cloudflare.com, github.com y los DNS 1.1.1.1 y 8.8.8.8 (DNS, HTTPS y ruta). Con la casilla desactivada solo queda el portal.
- El paquete de evidencia incluye datos de tu red y de tu teléfono y NO está cifrado (está firmado). La app lo avisa antes de exportar.
- Un informe hecho por el propio teléfono no demuestra su integridad si el teléfono está comprometido: exporta la evidencia y verifícala
  en otro equipo.

## Límites
- La salida de `cmd wifi`, `dumpsys` y `appops` cambia entre versiones y fabricantes: lo que no se entiende se ignora, y lo que no se pudo
  leer aparece en «Lo que no se pudo comprobar». No sustituye a un análisis forense profesional.
- La tabla OUI es parcial y orientativa. Las MAC aleatorias no tienen fabricante.
- La detección de gemelo malvado y de ARP spoofing son indicios, no pruebas: cada hallazgo explica los casos legítimos.
- Solo IPv4 en el barrido; no revisa UDP salvo las consultas DNS; no compara versiones con CVE. minSdk 26; ADB necesita Android 11+.
- No hay vigilancia continua en segundo plano (decisión de diseño: es una herramienta de análisis puntual).
- No se sondea SNMP: la consulta habitual usa la comunidad «public», que es una contraseña por defecto, y El Faro no prueba contraseñas.
- No hay captura pasiva de tráfico.
- Bluetooth: muchos dispositivos cambian su dirección, así que el nombre que les des puede no reconocerse la próxima vez; la detección de
  rastreadores es un indicio de una sola toma (no sabe si te siguen). El escaneo exige el permiso de ubicación en todas las versiones.
- La tabla de versiones es pequeña: que no salga nada no significa que el equipo esté al día, y puede haber falsos positivos si el fabricante
  corrige sin cambiar el número de versión.

## Cómo probarla
0. (2.1) Toca un equipo > «Renombrar…» y vuelve a analizar: debe conservar el nombre. Toca un hallazgo: debe ofrecer atajos a los ajustes.
   Abre «Análisis Bluetooth», concede los permisos y comprueba que aparece lo que tienes alrededor. Con un AirTag o SmartTag cerca debe
   salir «Posible rastreador».
1. «Solo router y red» en tu Wi-Fi: debe mostrar UPnP (reenvíos), DNS, HTTPS y ruta, además de lo de antes.
2. «Modo avanzado (ADB)»: emparejar y conectar (pantalla dividida para ver el código). Luego «Análisis forense total»:
   debe aparecer la tabla ARP con MAC y fabricante, y las secciones de Wi-Fi, conexiones y apps.
3. Repite el análisis forense: debe aparecer «Cambios desde la visita anterior» y una segunda entrada en el historial.
4. «Exportar evidencia firmada» y luego «Verificar un paquete de evidencia» con ese archivo: firma válida y hashes correctos.
   Edita un carácter del JSON y vuelve a verificar: debe dar NO VÁLIDA.
5. Importa una lista de IOC con una IP que sepas que tu teléfono contacta (por ejemplo la de un servidor que uses) y comprueba que salta.
