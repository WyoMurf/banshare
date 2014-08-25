#include <czmq.h>
#include "banshare-conf.h"
#include "clicert_banshare.h"
#include "server_ports.h"
#include <string.h>
#include <regex.h>
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

int enc = 1;
int debug = 1;

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
    openlog ("banshare-client", LOG_PID, LOG_DAEMON);
}

int rreplace (char *buf, int size, regex_t *re, char *rp)
{
	char *pos;
	int sub, so, n;
	regmatch_t pmatch [10]; /* regoff_t is int so size is int */
	if (regexec (re, buf, 10, pmatch, 0)) return 0;
	for (pos = rp; *pos; pos++)
	if (*pos == '\\' && *(pos + 1) > '0' && *(pos + 1) <= '9') {
		so = pmatch [*(pos + 1) - 48].rm_so;
		n = pmatch [*(pos + 1) - 48].rm_eo - so;
		if (so < 0 || strlen (rp) + n - 1 > size) return 1;
		memmove (pos + n, pos + 2, strlen (pos) - 1);
		memmove (pos, buf + so, n);
		pos = pos + n - 2;
	}
	sub = pmatch [1].rm_so; /* no repeated replace when sub >= 0 */
	for (pos = buf; !regexec (re, pos, 1, pmatch, 0); ) {
	n = pmatch [0].rm_eo - pmatch [0].rm_so;
		pos += pmatch [0].rm_so;
		if (strlen (buf) - n + strlen (rp) + 1 > size) return 1;
		memmove (pos + strlen (rp), pos + n, strlen (pos) - n + 1);
		memmove (pos, rp, strlen (rp));
		pos += strlen (rp);
		if (sub >= 0) break;
	}
	return 0;
}


int main(int argc, char **argv)
{
	char certdir[256];
	char servercert[512];

	skeleton_daemon();

	regex_t re1, re2, re3;
	if (regcomp(&re1, "SRCIP", 0)) {
		syslog(LOG_DAEMON|LOG_CRIT, "Could not compile SRCIP regex! What gives???\n");
		exit(10);
	}
	if (regcomp(&re2, "JAIL", 0)) {
		syslog(LOG_DAEMON|LOG_CRIT, "Could not compile JAIL regex! What gives???\n");
		exit(10);
	}
	if (regcomp(&re3, "PROG", 0)) {
		syslog(LOG_DAEMON|LOG_CRIT, "Could not compile PROG regex! What gives???\n");
		exit(10);
	}
	zctx_t *ctx = zctx_new();
	zauth_t *auth;
	zcert_t *cert, *server_public_cert;

	if (access("/etc/ssl/certs/banshare/", R_OK) == 0 ) { // ubuntu, CentOS 6.x
		strcpy(certdir, "/etc/ssl/certs/banshare");
		strcpy(servercert, "/etc/ssl/certs/banshare/server_banshare");
	} else if (access("/etc/pki/tls/certs/banshare/", R_OK) == 0 ) { // CentOS 5.x
		strcpy(certdir, "/etc/pki/tls/certs/banshare");
		strcpy(servercert, "/etc/pki/tls/certs/banshare/server_banshare");
	}

	if (enc) {
		auth = zauth_new(ctx);
		zauth_set_verbose(auth, true);
		zauth_configure_curve(auth, "*", certdir);
		cert = zcert_new_from(banshare_client_public, banshare_client_private);
		zcert_set_meta(cert, "name", "Client test certificate");

		server_public_cert = zcert_load(servercert);
	}
	void *sub_sock = zsocket_new(ctx, ZMQ_SUB); // further down, I'll figure out who to connect to and how.
	if (enc) {
		zcert_apply(cert, sub_sock);
		zsocket_set_curve_serverkey (sub_sock, zcert_public_txt(server_public_cert));
	}
	zmq_setsockopt (sub_sock, ZMQ_SUBSCRIBE, "", 0); // take everything
	int rc = zsocket_connect(sub_sock, "tcp://%s:%d", BANSHARE_SERVER_IP, SERVER_PUB_PORT);
	if (rc < 0) {
		syslog(LOG_DAEMON|LOG_CRIT, "Connect to server at %s:%d Failed with rc=%d\n", BANSHARE_SERVER_IP, SERVER_PUB_PORT, rc);
		exit(0);
	} else {
		syslog(LOG_DAEMON|LOG_NOTICE, "Connect to Sub port at %s:%d returns rc=%d, looking Good!\n", BANSHARE_SERVER_IP, SERVER_PUB_PORT, rc);
	}
	zclock_sleep(200);
	while (!zctx_interrupted) {
		char *m = zstr_recv(sub_sock);
		syslog(LOG_DAEMON|LOG_NOTICE, "Received %s\n", m);
		// HEY, some real work here to do: split the string into fields, grab the output format and 
		// string format:   <program-name>;<jail-name>;<banned-ip>
		char rbuf[1000];
		char nulljail[4];
		nulljail[0] = 0;
		strcpy(rbuf, m);
		char *progname = rbuf;
		char *jailname = strchr(rbuf,';');
		char *bannedip = (jailname ? strchr(jailname+1,';') : nulljail);
		char *senderip = strrchr(rbuf,';');

		if( !jailname || !bannedip || !senderip) {
			syslog(LOG_DAEMON|LOG_WARNING, "Hey! Got published message: %s, which has bad format; IGNORED!\n", m);
			continue;
		}
		*jailname = 0;
		jailname++;

		*bannedip = 0;
		bannedip++;

		*senderip = 0;
		senderip++;

                if(debug) syslog(LOG_DAEMON|LOG_NOTICE, "Parsed: prog=%s  jail=%s  ban=%s  from=%s\n", progname, jailname, bannedip, senderip);

		if( !strlen(bannedip)) {
			syslog(LOG_DAEMON|LOG_WARNING, "Hey! The bannedIP is null in this message: '%s'; That is destroys the whole purpose of making a report! IGNORED!\n", m);
			continue;
		}
		
		// do substitutions

		// The command can contain 'SRCIP' which is replaced with the banned ip number,
		// and JAIL, which is replaced with the jail name,
		// and PROG, which is replaced with the program name;  That gives you three fields to play with in forming your command!

		char buf[1024];
		strcpy(buf, BANSHARE_BAN_COMMAND);
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "Before substitution: %s\n", buf);
		rreplace(buf, sizeof(buf), &re1, bannedip);
		rreplace(buf, sizeof(buf), &re2, jailname);
		rreplace(buf, sizeof(buf), &re3, progname);
		if (debug)
		syslog(LOG_DAEMON|LOG_DEBUG, "After substitution: %s\n", buf);
		syslog(LOG_DAEMON|LOG_NOTICE, "Sending to Failban: %s\n", buf);	
		// oh, and the server cache's the IP's, and will skip another
		// ban of the same IP within 5 minutes of the last request. Hopefully,
		// that will calm a possible storm of activity if the addition of a ban 
		// causes another report to be issued.
		
		// and then do a system call to execute the command
		system(buf);
	}
	regfree(&re1);
	regfree(&re2);
	regfree(&re3);
	syslog(LOG_DAEMON|LOG_NOTICE, "Goodbye, Cruel World!\n");
	exit(0);
}
