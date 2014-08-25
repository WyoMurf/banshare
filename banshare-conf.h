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

// everyone needs this, and the user has to edit this to
// give the right ip where the banshare server will be run.

#define BANSHARE_SERVER_IP  "w.x.y.z"

// #define BANSHARE_BAN_COMMAND "/usr/bin/fail2ban-client set JAIL banip SRCIP"
#define BANSHARE_BAN_COMMAND "/usr/bin/fail2ban-ban-ip JAIL SRCIP PROG"
