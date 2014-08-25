#include <stdio.h>
#include <czmq.h>

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


int main(int argc, char **argv)
{
  char *a = argv[1];            // name of cert
  char sa[500];            // name of serv_cert
  char ca[500];            // name of client_cert
  uint8_t serv_priv[32];
  uint8_t serv_pub[32];
  uint8_t cli_priv[32];
  uint8_t cli_pub[32];
  zcert_t *serv_cert = zcert_new();
  zcert_t *cli_cert = zcert_new();

  uint8_t *serv_privp = zcert_secret_key(serv_cert);
  uint8_t *serv_pubp = zcert_public_key(serv_cert);

  uint8_t *cli_privp = zcert_secret_key(cli_cert);
  uint8_t *cli_pubp = zcert_public_key(cli_cert);

  memmove(serv_priv, serv_privp, sizeof(serv_priv));
  memmove(serv_pub, serv_pubp, sizeof(serv_pub));

  memmove(cli_priv, cli_privp, sizeof(cli_priv));
  memmove(cli_pub, cli_pubp, sizeof(cli_pub));

  char *serv_cprivp = zcert_secret_txt(serv_cert);
  char *serv_cpubp = zcert_public_txt(serv_cert);

  char *cli_cprivp = zcert_secret_txt(cli_cert);
  char *cli_cpubp = zcert_public_txt(cli_cert);

  char servhnam[1000];
  char clihnam[1000];

  sprintf(servhnam, "servcert_%s.h", a);
  sprintf(clihnam, "clicert_%s.h", a);

  FILE *serv = fopen(servhnam, "w");
  FILE *cli  = fopen(clihnam, "w");

  fprintf(serv, "char *%s_server_private_txt = \"%s\";\n", a, serv_cprivp);
  fprintf(serv, "char *%s_server_public_txt = \"%s\";\n\n\n", a, serv_cpubp);
  fprintf(cli, "char *%s_cli_private_txt = \"%s\";\n", a, cli_cprivp);
  fprintf(cli, "char *%s_cli_public_txt = \"%s\";\n\n\n", a, cli_cpubp);

  sprintf(sa, "server_%s", a);
  sprintf(ca, "client_%s", a);

  zcert_save(serv_cert, sa);
  zcert_save(cli_cert, ca);

  // we don't need the secret keys on disk; just a security hazard
  unlink("server_banshare_secret");
  unlink("client_banshare_secret");

  fprintf
    (serv, "uint8_t %s_server_private[32] = {0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx };\n",
     a, serv_priv[0], serv_priv[1], serv_priv[2], serv_priv[3], serv_priv[4], serv_priv[5], serv_priv[6],
     serv_priv[7], serv_priv[8], serv_priv[9], serv_priv[10], serv_priv[11], serv_priv[12], serv_priv[13],
     serv_priv[14], serv_priv[15], serv_priv[16], serv_priv[17], serv_priv[18], serv_priv[19], serv_priv[20],
     serv_priv[21], serv_priv[22], serv_priv[23], serv_priv[24], serv_priv[25], serv_priv[26], serv_priv[27],
     serv_priv[28], serv_priv[29], serv_priv[30], serv_priv[31]);
  fprintf
    (serv, "uint8_t %s_server_public[32] = {0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx };\n",
     a, serv_pub[0], serv_pub[1], serv_pub[2], serv_pub[3], serv_pub[4], serv_pub[5], serv_pub[6], serv_pub[7],
     serv_pub[8], serv_pub[9], serv_pub[10], serv_pub[11], serv_pub[12], serv_pub[13], serv_pub[14], serv_pub[15],
     serv_pub[16], serv_pub[17], serv_pub[18], serv_pub[19], serv_pub[20], serv_pub[21], serv_pub[22], serv_pub[23],
     serv_pub[24], serv_pub[25], serv_pub[26], serv_pub[27], serv_pub[28], serv_pub[29], serv_pub[30], serv_pub[31]);

  fprintf
    (cli, "uint8_t %s_client_private[32] = {0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx };\n",
     a, cli_priv[0], cli_priv[1], cli_priv[2], cli_priv[3], cli_priv[4], cli_priv[5], cli_priv[6],
     cli_priv[7], cli_priv[8], cli_priv[9], cli_priv[10], cli_priv[11], cli_priv[12], cli_priv[13],
     cli_priv[14], cli_priv[15], cli_priv[16], cli_priv[17], cli_priv[18], cli_priv[19], cli_priv[20],
     cli_priv[21], cli_priv[22], cli_priv[23], cli_priv[24], cli_priv[25], cli_priv[26], cli_priv[27],
     cli_priv[28], cli_priv[29], cli_priv[30], cli_priv[31]);
  fprintf
    (cli, "uint8_t %s_client_public[32] = {0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,\n             0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx,0x%hhx };\n",
     a, cli_pub[0], cli_pub[1], cli_pub[2], cli_pub[3], cli_pub[4], cli_pub[5], cli_pub[6], cli_pub[7],
     cli_pub[8], cli_pub[9], cli_pub[10], cli_pub[11], cli_pub[12], cli_pub[13], cli_pub[14], cli_pub[15],
     cli_pub[16], cli_pub[17], cli_pub[18], cli_pub[19], cli_pub[20], cli_pub[21], cli_pub[22], cli_pub[23],
     cli_pub[24], cli_pub[25], cli_pub[26], cli_pub[27], cli_pub[28], cli_pub[29], cli_pub[30], cli_pub[31]);

  fclose(serv);
  fclose(cli);
  exit(0);
}

