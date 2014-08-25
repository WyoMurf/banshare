#include <czmq.h>
#include "banshare-conf.h"
#include "clicert_banshare.h"
#include "server_ports.h"
#include <ifaddrs.h>

// Copyright (C) 2014 Steve Murphy
// All Rights Reserved
// License (GNU Public License):
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program; if not, write to the Free Software
//    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
//    USA
//

// The args to this program:
//                 // string format:   <program-name>;<jail-name>;<banned-ip>
//  banshare-report  <program-name> <jail-name>  <banned-ip>

int enc=1;
int debug=0;
char *server_ip = BANSHARE_SERVER_IP;
char this_ip[2000];

int server_is_local(void)
{
	int retval = 0;
	char *externip;
	// see if the ip addr of the server matches any assigned to interfaces.
	this_ip[sizeof(this_ip)-1] = 0;
	gethostname(this_ip, sizeof(this_ip)-1);
	struct ifaddrs *addrs,*tmp;
	getifaddrs(&addrs);
	for (tmp=addrs; tmp; tmp=tmp->ifa_next) {
		struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
		if (strstr(tmp->ifa_name, "eth") && !strstr(inet_ntoa(pAddr->sin_addr),"0.0.0") ) {
			char bufn[1024];
                        sprintf(bufn, "/%s:%s", tmp->ifa_name, inet_ntoa(pAddr->sin_addr));
                        strncat(this_ip,bufn,sizeof(this_ip));
                }
		if( !strcmp(server_ip, inet_ntoa(pAddr->sin_addr))) {
			retval=1;
		}
	}
	freeifaddrs(addrs);

	// see if the ip addr of the server matches our internet address
	int isthere = access("/tmp/banshare-ext-ip", R_OK);
	if (isthere) {
		char *cmd = "curl -s http://checkip.dyndns.org/ | cut -d ' ' -f 6 | sed 's@</body></html>@@' > /tmp/banshare-ext-ip";
		system(cmd);
	}
	isthere = access("/tmp/banshare-ext-ip", R_OK);
	if( isthere == 0) {
		FILE *x = fopen("/tmp/banshare-ext-ip", "r");
		if (x) {
			char buf[20];
			fgets(buf, sizeof(buf), x);
			while (buf[strlen(buf)-1] == '\r' || buf[strlen(buf)-1] == '\n')
				buf[strlen(buf)-1] = 0;
			externip = buf;
			if (strcmp(server_ip, buf) == 0)
				retval=1;
		}
	}
	strncat(this_ip,"/extern:",sizeof(this_ip));
        strncat(this_ip,externip,sizeof(this_ip));
	return retval;
}

int main(int argc, char **argv)
{
	if( argc < 4 ) {
		printf("HEY! Usage:\n   banshare-report [-d] <program-name>  <jail-name>  <banned-ip>\n\n");
		printf("                   where -d sets debug mode\n");
		exit(1);
	}
	int baseind = 1;
	if( argv[1][0] == '-' && argv[1][1] == 'd') {
		debug = 1;
		baseind = 2;
	}
	char *progname = argv[baseind];
	char *jailname = argv[baseind+1];
	char *bannedip = argv[baseind+2];
        zauth_t *auth;
        zcert_t *cert;
       	zcert_t *server_public_cert;
	char certdir[256];
	char servercert[512];

	if (access("/etc/ssl/certs/banshare/", R_OK) == 0 ) { // ubuntu, CentOS 6.x
		strcpy(certdir, "/etc/ssl/certs/banshare");
		strcpy(servercert, "/etc/ssl/certs/banshare/server_banshare");
	} else if (access("/etc/pki/tls/certs/banshare/", R_OK) == 0 ) { // CentOS 5.x
		strcpy(certdir, "/etc/pki/tls/certs/banshare");
		strcpy(servercert, "/etc/pki/tls/certs/banshare/server_banshare");
	}

	zctx_t *ctx = zctx_new();
	if (enc) {
        	auth = zauth_new (ctx);
        	zauth_set_verbose (auth, true);
        	zauth_configure_curve (auth, "*", certdir);
        	cert = zcert_new_from(banshare_client_public, banshare_client_private);

       	 	server_public_cert = zcert_load(servercert);
	}

	void *rep_sock = zsocket_new(ctx, ZMQ_REQ); // This will be request socket to complement the server's REP socket!
	if (enc) {
        	zcert_apply (cert, rep_sock);

        	zsocket_set_curve_serverkey (rep_sock, zcert_public_txt(server_public_cert));
	}
	zsocket_set_rcvtimeo(rep_sock, 3000); // set read and write timeouts to 3 sec.
	zsocket_set_sndtimeo(rep_sock, 3000);
	int rc;
 	char *servip;
	if (server_is_local()) {
		servip = "127.0.0.1";
	} else {
		servip = BANSHARE_SERVER_IP;
	}
       	rc = zsocket_connect(rep_sock, "tcp://%s:%d", servip, SERVER_REPORT_PORT);

	if (rc != 0) {
		printf("Connect to REQ socket to %s:%d FAILED with rc=%d\n", servip, SERVER_REPORT_PORT, rc);
		exit(0);
	}
	if (debug) printf("Connected to tcp://%s:%d Just fine...\n", servip, SERVER_REPORT_PORT);
	zclock_sleep(500);
        while (!zctx_interrupted) {
		char buf[1000]; 
		int ret1 = zstr_sendf(rep_sock, "%s;%s;%s;%s", progname, jailname, bannedip, this_ip);
		if (ret1 == -1) {
			printf("Timeout while sending report! Server is DOWN?\n");
			exit(1);
		}
		if( debug) printf("Sent: %s;%s;%s;%s to %s\n", progname, jailname, bannedip, this_ip, servip);
		// and like all good req-rep sockets, we should get a response!
		char *rec = zstr_recv(rep_sock);
		if (!rec) {
			printf("Timeout while waiting for OK! Server is DOWN?\n");
			exit(1);
		}

		if (debug) printf("Got %s back from server\n", rec);
		zstr_free(&rec);
		// Oh, all that was really difficult, wasn't it? we are done. disconnect and exit
		exit(0);
	}
}
