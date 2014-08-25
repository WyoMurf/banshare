banshare
========

Using fail2ban/psad, and when probes are detected, automatically have all your hosts ban the bad guys.

This program written by Steve Murphy

Copyright (C) 2014 Steve Murphy, All Rights Reserved

License: GNU GPL


This package will allow a detection/blocking response for any package that
has the capability to run a user-defined external script when a security event
has been detected.  Thus, dozens/hundreds/thousands
of machines can act as "attack sensors", and the entire set of systems can 
respond together as a unit to block the attack on each participating system.
This is useful, because it has been noted that scans and attacks on one machine
in a set in a cloud, will often be repeated on the others. This kind of capability
is provided by OSSEC, but only within their own detection framework, and OSSEC provides
a fairly rigid framework for adding new agents.

This small package introduces 2 daemons, a server and a client. Also included
is a reporter that reports a ban to the server, via a "report" request-reply 
socket. When a ban is reported to the server, it publishes the ban to all clients
subscribing to the server. Clients run a command to ban the IP, which is configurable.

This package uses ZeroMQ for interprocess communication, with the libsodium 
packet encryption facility. The server will act the encryption server, and the
reporter and clients act as clients in their encrypted exchanges.

The keys for encryption, and the port numbers used for communication,
will be assigned on a per-build basis, thus making each build unique,
which hopefully will make things a bit more secure against external scanning,
and against client or reporter spoofing. It might be good practice to 
"make regen" every day/week/month or so, and redeploy the clients and server,
as this kind of activity will make it fairly difficult for hackers, unless they
can get internal access to your source machines.

Experience says that attacks against servers in one IP range may not extend to
attacks on a different ip range. Thus, you may want to split any cloud farms
into groups of individual cloud providers, and run a banshare-server on each
group. Or, you can use one server, and all clouds will ban all the IP's together.
It's up to you. You can run the client and server on the same machine if you want.
The clients, though, should run on the machines running failban (or other detection
packages).

This package allows you to build a "client-install.sh" and a "server-install.sh",
which you can transport to machines and run. A server can run on any machine,
including a machine that also runs a client. The reporter will attach to the server via an 
external IP if that ip isn't assigned a local interface, and isn't its external
IP (if it is behind a firewall). If the server is local, it will connect to it
via 172.0.0.1.

The server has its libsodium/zeromq certificates compiled in, as do the client and reporter.
The public certs are distributed to all client and server machines as part of the
install process. Some have pointed out the folly of this sort of operation, but
my intention is to protect the communication path; If hackers can get into your
machines, the battle is lost either way. Possible attack vectors are that they grab your
reporter, and use it to ban IP's you might be using... My suggestion is to 
use the ignoreIP feature in failban to whitelist your machines and protect them
from banning, and the autodl file in psad to protect your pachines also. 
And, in case of such attacks, regenerate a new set of certs and 
use new ports, and redeploy. I suggest automating the deployment as much as
possible.

This package comes set up mostly for fail2ban; but any package that allows you
to run an external command to introduce a new ban, and will allow you to run
an external command when a ban is instituted, could be integrated to use this
facility. Psad, as of version 2.2.4, has the has the EXTERNAL_BLOCK_SCRIPT
config parameter, which allows you run a script to report a block. You can also add
blocks with a psad command, so psad can also be used in a banshare environment.



Setting up for fail2ban:

A. in banshare-conf.h, define the IP where you will run the server, and make
   sure the BANSHARE_BAN_COMMAND defines the appropriate ban command. By default
   it is set to:
          /usr/bin/fail2ban-client set JAIL banip SRCIP

   (JAIL and SRCIP are substituted before issueing the command.)

B. Add a call to banshare-report to your "actionban" statement in your
   /etc/fail2ban/action.d/xxxx file(s):

         actionban = iptables -I fail2ban-<name> 1 -s <ip> -j DROP
                     /usr/bin/banshare-report fail2ban <jail> <ip>

C. Make sure to include the name of the jail in your action(s) in your
   jail.conf file. For example:

         [zzzzzz-iptables]
         enabled  = true
         filter   = zzzzzz
         action   = iptables-allports[name=ZZZZZZ, chain=drop-rules-INPUT, protocol=all, jail=zzzzzz-iptables]
                    sendmail-whois[name=ZZZZZZ, dest=alerts@yourcompany.com, sender=santa-alert@northpole.christmas.com]
         logpath  = /var/log/zzzzzz/messages
         maxretry = 5
         bantime = 259200

   Note the "jail=zzzzzz-iptables" entry in the iptables-allports action. Note that the zzzzzz-iptables matches the
   name of the jail. 

D. Reload fail2ban

   fail2ban-client reload

Do the same thing on all machines running the banshare-client.



Setting up for psad:
 
A. In psad.conf, for versions of psad >= 2.2.4, set ENABLE_EXT_BLOCK_SCRIPT_EXEC to Y:
    ENABLE_EXT_BLOCK_SCRIPT_EXEC  Y;

   And, set EXTERNAL_BLOCK_SCRIPT to report the block:  
    EXTERNAL_BLOCK_SCRIPT   /usr/bin/banshare-report psad anything SRCIP;

B. in banshare-conf.h, define the IP where you will run the server, and make
   sure the BANSHARE_BAN_COMMAND defines the appropriate ban command. By default
   it is set to:
          /usr/bin/fail2ban-client set JAIL banip SRCIP

   If you are running just psad, you can set this to:

	  psad --fw-block-ip SRCIP

   If you are running both, or maybe several different 
   packages, you should invoke a script you would write to
   apply the block to the proper chain.

   (JAIL and SRCIP are substituted before issueing the command.)

   Both psad and fail2ban have white-listing capabilities. I suggest
   you use them to thoroughly protect all your valid hosts, or, at some
   point, you will find yourself wishing that you had.

There. now you have psad reporting blocks to the banshare server,
and accepting block commands from the banshare clients.

CLIENT
======

The clients listen to the server on a pub-sub socket. When they receive a
message from the server, they execute a psad/fail2ban command to block the
associated IP. If you are running fail2ban or psad (or both), you might want
to run the client on that machine.

For fail2ban, the command to use to introduce a block is:

fail2ban-client set <JAIL> banip <IP>

for psad, the command to use:

psad --fw-block-ip <ip>

You set #define BAN_COMMAND in the client source to the desired command:

"/usr/bin/fail2ban-client set <JAIL> banip <IP>" and the client
will replace the <JAIL> and <IP> with their respective values before issueing the
command. If you have both (or more) packages running, usually you only have to
ban from one package. Any others would be "overkill".

The script "fail2ban-ban-ip" is provided as something you can call via the BAN_COMMAND
macro, as it can handle the differences between different versions of fail2ban, and can
call psad if it is present, and the action was detected by psad.


SERVER
======

The server can have any number of clients attached to its pub socket.
Each client will only be attached to a single server. The server has a
req/rep socket, which reporters attach to long enough to report a ban.
The ban report should contain:
   a. The program making the report (fail2ban/psad/whatever)
   b. The jail or some other discriminator associated with the ban.
   c. The IP of the machine being banned

This info is passed to the clients via the pub socket, and they
use it in the banip command.

The server internally keeps a table of reported bans, and will not repeat a ban
already made in the last 5 minutes. (This might help, should a ban cause a 
ban to be reported... let's avoid this kind of loop!)

Firewalls: Since the server is listening on two ports, you may have to 
redirect those ports on your firewall, if, of course, your server machine
is behind a firewall! And I hope it is! Those two ports are chosen at
random at the beginning of the compile, if the file "server_ports.h" does
not exist. ( "make regen" will erase this file. ) If you cat this file,
you will see something like this:

#define SERVER_REPORT_PORT 51550
#define SERVER_PUB_PORT    21257

So, in this case, make sure to redirect incoming connections on ports 51550 and 21257
to the machine running your server. You might also restrict the origin of these
requests to the IP ranges of your machines.

These port numbers are randomly generated by the gen_ports script in this
release. The range is from 20000 to 64000, which should make scanning for
these ports rather "interesting". I suggest restricting the ip ranges from
whence these requests will be originating, and running psad to keep out the
bad guys.



REPORTER
========

The banshare-report exec requires 3 arguments:
   banshare-report <prog> <jail> <ip>

The reporter is meant to be run from the failban/psad/whatever, as an external 
script. You can insert it into the fail2ban action scripts for banning.

I include a patch to psad-2.2.3, that introduces 2 new definitions in
psad.conf, 

ENABLE_EXT_BLOCK_SCRIPT_EXEC
EXTERNAL_BLOCK_SCRIPT

(Michael Rash includes this code in psad version 2.2.4.)


The patch changes the version to 2.2.3b.

enter this (or something more appropriate for your setup):

ENABLE_EXT_BLOCK_SCRIPT_EXEC Y;
EXTERNAL_BLOCK_SCRIPT   /usr/bin/banshare-report psad anything SRCIP;

The "anything" as a jail name can be used as a clue to the fail2ban-ban-ip script
(fired up by the client, if you wish), that this ban originates from psad. We could
just as easily used "psad" for  a jail name, I guess!




Building

Edit the banshare-conf.h file, and set the IP where you are going to run your server.

To build the execs:

     make

To rebuild the execs, so they use a new set of ports and certificates:

     make regen
     make

To just change the certs:

    rm {client,server}_banshare {cli,serv}cert_banshare.h
    make

To generate install script(s):

     make client-install.sh
     (then send this client-install.sh to all your fail2ban machines. It contains a tar file with the programs/certs/etc.)

same for the server:

     make server-install.sh


32 vs. 64 bit:

     I have some provision to build 32 bit objects on a 64 bit machine. But I can't link on a 64-bit
     machine. So, I suggest copying the source to a 32 bit machine, build a set of 32-bit execs via:

       make 32

     then, grab the results and throw them in the 32 folder on your 64-bit machine. The {client/server} install scripts
     will contain the both sets, and the script will install the 64-bit versions if /lib64 is found, else install the
     32 bit versions.  Also, two tar files with the libsodium and libzmq and libczmq libraries are included, both
     32 bit and 64 bit, compiled under centos. If you don't have these libraries on your machines, the install script
     will throw them into /usr/lib.  I am using zeromq-4.0.4 and czmq-2.2.0, fairly late model releases, along with the
     latest libsodium at this time, libsodium-0.6.1.



