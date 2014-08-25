## banshare-conf.h  clicert_banshare.h  servcert_banshare.h

all: 64/gen_certs2 64/banshare-client 64/banshare-server 64/banshare-reporter
    

regen:
	rm servcert_banshare.h clicert_banshare.h server_banshare client_banshare server_ports.h


servcert_banshare.h clicert_banshare.h server_banshare client_banshare : 
	64/gen_certs2 banshare

server_ports.h : 
	./gen_ports

64/gen_certs2 : gen_certs2.c
	gcc -o 64/gen_certs2 gen_certs2.c -lczmq

64/banshare-server : 64/banshare-server.o
	gcc -g -o 64/banshare-server 64/banshare-server.o -lczmq -lzmq

64/banshare-client : 64/banshare-client.o
	gcc -g -o 64/banshare-client 64/banshare-client.o -lczmq -lzmq

64/banshare-reporter : 64/banshare-reporter.o 
	gcc -g -o 64/banshare-reporter 64/banshare-reporter.o -lczmq -lzmq

64/banshare-server.o : banshare-server.c banshare-conf.h server_ports.h servcert_banshare.h
	gcc -c -g -o 64/banshare-server.o banshare-server.c

64/banshare-client.o : banshare-client.c banshare-conf.h server_ports.h clicert_banshare.h servcert_banshare.h
	gcc -c -g -o 64/banshare-client.o banshare-client.c

64/banshare-reporter.o : banshare-reporter.c banshare-conf.h server_ports.h clicert_banshare.h servcert_banshare.h
	gcc -c -g -o 64/banshare-reporter.o banshare-reporter.c


## 32 bit versions

32/banshare-server : 32/banshare-server.o
	gcc -g -o 32/banshare-server 32/banshare-server.o -lczmq -lzmq

32/banshare-client : 32/banshare-client.o
	gcc -g -o 32/banshare-client 32/banshare-client.o -lczmq -lzmq

32/banshare-reporter : 32/banshare-reporter.o 
	gcc -g -o 32/banshare-reporter 32/banshare-reporter.o -lczmq -lzmq

32/banshare-server.o : banshare-server.c banshare-conf.h server_ports.h servcert_banshare.h
	gcc -c -g -o 32/banshare-server.o banshare-server.c

32/banshare-client.o : banshare-client.c banshare-conf.h server_ports.h clicert_banshare.h servcert_banshare.h
	gcc -c -g -o 32/banshare-client.o banshare-client.c

32/banshare-reporter.o : banshare-reporter.c banshare-conf.h server_ports.h clicert_banshare.h servcert_banshare.h
	gcc -c -g -o 32/banshare-reporter.o banshare-reporter.c

32 : 32/banshare-server 32/banshare-client 32/banshare-reporter

	
deploy-server : 64/banshare-server 32/banshare-server client_banshare  server_banshare
	(cd ..; tar czvf deploy-server.tar.gz banshare/64/banshare-server banshare/client_banshare  banshare/server_banshare banshare/server-install banshare/server_ports.h banshare/init-server banshare/fire.php 32/banshare-server 32/banshare-client 32/banshare-reporter)

client-install.sh : 64/banshare-client 64/banshare-reporter client_banshare  server_banshare init-client mqlibs64.tar.gz mqlibs32.tar.gz
	(cd ..; tar czf deploy-clients.tar.gz banshare/64/banshare-client banshare/64/banshare-reporter banshare/32/banshare-client banshare/32/banshare-reporter banshare/client_banshare  banshare/server_banshare  banshare/init-client banshare/mqlibs32.tar.gz banshare/mqlibs64.tar.gz banshare/safe_banshare_client banshare/fail2ban-ban-ip.v0.8.10  banshare/fail2ban-ban-ip.v0.8.4  banshare/fail2ban-ban-ip.v0.8.5  banshare/fail2ban-ban-ip.v0.8.6  banshare/fail2ban-ban-ip.v0.8.7  banshare/fail2ban-ban-ip.v0.8.8 )
	(cd ..; uuencode deploy-clients.tar.gz deploy-clients.tar.gz > deploy-clients.tar.gz.uue)
	(cd ..; cat banshare/client-install deploy-clients.tar.gz.uue banshare/client-install3 > banshare/client-install.sh)
	chmod a+x client-install.sh
	(cd ..; rm deploy-clients.tar.gz deploy-clients.tar.gz.uue)

server-install.sh : 64/banshare-server server_banshare init-server mqlibs32.tar.gz mqlibs64.tar.gz
	(cd ..; tar czvf deploy-server.tar.gz banshare/64/banshare-server banshare/32/banshare-server banshare/client_banshare  banshare/server_banshare  banshare/init-server banshare/mqlibs32.tar.gz banshare/mqlibs64.tar.gz banshare/fire.php banshare/safe_banshare_server)
	(cd ..; uuencode deploy-server.tar.gz deploy-server.tar.gz > deploy-server.tar.gz.uue)
	(cd ..; cat banshare/server-install deploy-server.tar.gz.uue banshare/server-install3 > banshare/server-install.sh)
	chmod a+x server-install.sh
	(cd ..; rm deploy-server.tar.gz deploy-server.tar.gz.uue)


