#include <czmq.h>
#include "banshare-conf.h"
#include "servcert_banshare.h"
#include "clicert_banshare.h"
#include "server_ports.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

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

static void skeleton_daemon(void)
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
    {
        close (x);
    }

    openlog ("banshare-server", LOG_PID, LOG_DAEMON);
}

struct ipcache
{
  char ip[18];
  time_t tstamp;
};

int clean_ipcache(const char *key, void *item, void *argument)
{
	zhash_t *tab = argument;
	struct ipcache *x = item;
	if (x->tstamp + 300 < time(0)) {
		zhash_delete(tab, key);
	}
}

// the above includes will bring in something like this:
// #define BANSHARE_SERVER_IP  "XXX.XXX.XXX.XXX"


// char *banshare_server_public_txt = "u34%wpq-pNRC@0z>eN{bYqoTfypA&Loc/nR=KUKG";


// uint8_t banshare_server_public[32] = {0x5d,0x74,0x35,0xc3,0x4e,0xc3,0x93,0xe0,
//              0xa6,0x54,0x7d,0xff,0xe6,0xc7,0xd,0x4f,
//              0xbb,0xa5,0x75,0x38,0x6a,0xb7,0xf4,0xc2,
//              0x4b,0x24,0x86,0xe9,0xcf,0xf,0x80,0x20 };
// char *banshare_server_private_txt = "8d>D67kidrFlJt8Stdv9{9+uFS=jr5.}X<+OC<26";
// uint8_t banshare_server_private[32] = {0x19,0x66,0x2d,0x4,0x16,0x85,0xb,0xc9,
//              0x80,0x5b,0x9,0x78,0xa9,0x15,0x37,0x68,
//              0xf6,0x28,0x7d,0x8c,0xaa,0x70,0x97,0xa7,
//              0xc3,0xdc,0x66,0x8f,0x9c,0xfe,0xe,0xb1 };
// #define SERVER_REPORT_PORT 34819
// #define SERVER_PUB_PORT    43787

// banshare-conf.h  clicert_banshare.h  servcert_banshare.h  server_ports.h

int enc = 1;
int debug = 1;

int main(int argc, char **argv)
{
	char certdir[256];
	char servercert[512];

	skeleton_daemon();

	zhash_t *ip_cache = zhash_new();
	zctx_t *ctx = zctx_new();
	zcert_t *cert;
	zauth_t *auth;
	
	if (access("/etc/ssl/certs/banshare/", R_OK) == 0 ) { // ubuntu, CentOS 6.x
		strcpy(certdir, "/etc/ssl/certs/banshare");
		strcpy(servercert, "/etc/ssl/certs/banshare/server_banshare");
	} else if (access("/etc/pki/tls/certs/banshare/", R_OK) == 0 ) { // CentOS 5.x
		strcpy(certdir, "/etc/pki/tls/certs/banshare");
		strcpy(servercert, "/etc/pki/tls/certs/banshare/server_banshare");
	}

	if (enc) {
		cert = zcert_new_from(banshare_server_public, banshare_server_private);
		auth = zauth_new(ctx);
		zauth_set_verbose(auth, false);
		zauth_configure_curve(auth, "*", certdir);
	}

	void *server_report = zsocket_new(ctx, ZMQ_REP);
	if (enc) {
		zcert_apply(cert, server_report);
		zsocket_set_curve_server(server_report, 1);
	}

	int pnum = zsocket_bind(server_report, "tcp://*:%d", SERVER_REPORT_PORT);
	if (pnum <= 0) {
		syslog(LOG_DAEMON|LOG_WARNING, "HEY! The bind to the REPORT port %d at %s didn't work!(%d)\n", SERVER_REPORT_PORT, BANSHARE_SERVER_IP,pnum);
		exit(0);
	} else {
		if (debug)
		syslog(LOG_DAEMON|LOG_NOTICE, "BIND to Report Reply Socket at *:%d returns %d... looks good!\n", SERVER_REPORT_PORT, pnum);
	}


	void *server_pub = zsocket_new(ctx, ZMQ_PUB);
	if (enc) {
		zcert_apply(cert, server_pub);
		zsocket_set_curve_server(server_pub, 1);
	}
	
	int pnum2 = zsocket_bind(server_pub, "tcp://*:%d", SERVER_PUB_PORT);
	if (pnum2 <= 0) {
		syslog(LOG_DAEMON|LOG_WARNING,"HEY! The bind to the PUB port %d at %s didn't work!\n", SERVER_PUB_PORT, BANSHARE_SERVER_IP);
		exit(0);
	} else {
		if (debug)
		syslog(LOG_DAEMON|LOG_NOTICE,"BIND to Pub Socket at *:%d returns %d... looks good!\n",  SERVER_PUB_PORT, pnum2);
	}

	syslog(LOG_DAEMON|LOG_NOTICE, "banshare_server successfully bound to sockets and Ready For Action!\n");
	zclock_sleep(200); // wait 200msec

	while (!zctx_interrupted) {
		syslog(LOG_DAEMON|LOG_NOTICE,"About to call zstr_recv for the report socket");
		char *req = zstr_recv(server_report);
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "Server got: %s\n", req);
		// Now, send the response
		if( zctx_interrupted )
			break;
		char response_buf[1000];
		strcpy(response_buf, "OK");
		zstr_sendf(server_report, "%s", response_buf);
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "Server sent out OK\n");

		// split up the request string
                strcpy(response_buf, req);
                char *progname = response_buf;
                char *jailname = strchr(response_buf,';');
                char *bannedip = strchr(jailname+1,';');
                char *senderip = strrchr(response_buf,';');

                if( !jailname || !bannedip || !senderip) {
                        syslog(LOG_DAEMON|LOG_WARNING, "Hey! Got published message: %s, which has bad format; IGNORED!\n", req);
			zstr_free(&req);
                        continue;
                }
                *jailname = 0;
                jailname++;

                *bannedip = 0;
                bannedip++;

		*senderip = 0;
		senderip++;

                if( !strlen(bannedip)) {
                        syslog(LOG_DAEMON|LOG_WARNING, "Hey! The bannedIP is null in this message: '%s'; That is destroys the whole purpose of making a report! IGNORED!\n", req);
			zstr_free(&req);
                        continue;
                }

		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "OK, split the string into: %s, %s, %s, %s\n", progname, jailname, bannedip, senderip);

		// first, clean old entries out of the cache...
		int numx = zhash_size(ip_cache);
		zhash_foreach(ip_cache, clean_ipcache, ip_cache); // the last arg is passed into every clean_ipcache call!
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "Cleaned IP cache of old entries; had=%d; now=%zd\n", numx, zhash_size(ip_cache));

		// If we've already sent out a pub of this ip in the last 5 minutes, don't bother...
		struct ipcache *x = zhash_lookup(ip_cache, bannedip);
		if (x) {
			time_t now=time(0);
			if (debug)
			syslog(LOG_DAEMON|LOG_DEBUG, "Tossing out report of %s; got a report of that %d seconds ago!\n", bannedip, (int)(now-x->tstamp));
			x->tstamp = time(0); // refesh the time stamp
			zstr_free(&req);
			continue;  // we've already seen this, move on...
		} else {
			struct ipcache *x = malloc(sizeof(struct ipcache));
			strcpy(x->ip, bannedip);
			x->tstamp = time(0);
			zhash_insert(ip_cache, x->ip, x);
			zhash_freefn(ip_cache, x->ip, free);
			if (debug)
			syslog(LOG_DAEMON|LOG_DEBUG, "Inserted %s into IP cache.\n", bannedip);
		}
		if (debug)
		syslog(LOG_DAEMON|LOG_INFO, "Banshare Server Publishing ban: %s\n", req);
		zstr_send(server_pub, req); // pass it straight thru!!
		zstr_free(&req);
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "Server finished sending pub\n");
	}
	zhash_destroy(&ip_cache);
	syslog(LOG_DAEMON|LOG_NOTICE, "Goodbye, Cruel World!\n");
	closelog();
	// should I unbind my sockets, or is death sufficient?
}
