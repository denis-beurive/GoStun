// Copyright (C) 2012 Denis BEURIVE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import "stun"
import "fmt"
import "os"
import "net"
import "flag"
import "strconv"
import "tools"

func main() {
	var err error
	var serverHost *string  = flag.String("host", "",  "Host name for the STUN server.")
	var serverPort *int     = flag.Int("port",    3478, "Pot number for the host server.")
	var verbosityLevel *int = flag.Int("verbose", 0,    "Verbosity level.")
	var ips []string
	var ip string
	var nat int
		
	// Parse the command line.
	flag.Parse()
	
	if ("" == *serverHost) {
		fmt.Println("ERROR: You must specify the host name of the STUN server (option -host).")
		os.Exit(1)
	}
	
	// Lookup the host name.
	ips, err = net.LookupHost(*serverHost)
	if nil != err {
		fmt.Println(fmt.Sprintf("ERROR: %s", err))
		os.Exit(1)
	}
	
	if 0 == len(ips) {
		fmt.Println(fmt.Sprintf("ERROR: Can not lookup host \"%s\".", *serverHost))
		os.Exit(1)
	}

	fmt.Println(fmt.Sprintf("% -15s: %s", "Host", *serverHost))
	fmt.Println(fmt.Sprintf("% -15s: %d", "Port", *serverPort))
	fmt.Println(fmt.Sprintf("% -15s: IP%d = %s", "IPs", 0, ips[0]))
	for i:=1; i<len(ips); i++ {
		fmt.Println(fmt.Sprintf("% -15s: IP%d = %s", " ", i, ips[i]))
	}
	fmt.Println("\n\n")
	
	if len(ips) > 1 {
		fmt.Println(fmt.Sprintf("The given host name is associated to %d IP addresses.", len(ips)))
		fmt.Println(fmt.Sprintf("Which one should I use?"))
		
		
		for {
			var response string
			var idx int
			
			fmt.Println(fmt.Sprintf("\nPlease, enter an integer between 0 (for IP0) and %d (for IP%d).", len(ips)-1, len(ips)))	
			fmt.Scanln(&response)
			
			idx, err = strconv.Atoi(response)
			if (nil != err) {
				fmt.Println(fmt.Sprintf("The given value (%s) is not valid.", response))
				continue;
			}
			
			if (idx<0) || (idx>=len(ips)) {
				fmt.Println(fmt.Sprintf("The given value (%d) is not valid.", idx))
				continue;
			}

			ip, err = tools.MakeTransportAddress(ips[idx], *serverPort)
			_ = err 
			break;
		}
	} else {
		ip, err = tools.MakeTransportAddress(ips[0], *serverPort)
		_ = err
	}
	fmt.Println(fmt.Sprintf("\nUsing transport address \"%s\".\n", ip))
	
	// Perform discovery.
	stun.ClientInit(ip)
	stun.ActivateOutput(*verbosityLevel, nil)
	
	nat, err = stun.ClientDiscover()
	if (nil != err) {
		fmt.Println(fmt.Sprintf("An error occured: %s", err))
		os.Exit(1)
	}
	
	// Print result.
	fmt.Println("\n\nCONCLUSION\n")
	
	switch nat {
		case stun.STUN_NAT_ERROR:
			fmt.Println(fmt.Sprintf("Test failed: %s", err))
		case stun.STUN_NAT_BLOCKED:
			fmt.Println(fmt.Sprintf("UDP is blocked."))
		case stun.STUN_NAT_UNKNOWN:
			fmt.Println(fmt.Sprintf("Unexpected response from the STUN server. All we can say is that we are behind a NAT."))
		case stun.STUN_NAT_FULL_CONE:
			fmt.Println(fmt.Sprintf("We are behind a full cone NAT."))
		case stun.STUN_NAT_SYMETRIC:
			fmt.Println(fmt.Sprintf("We are behind a symetric NAT."))
		case stun.STUN_NAT_RESTRICTED:
			fmt.Println(fmt.Sprintf("We are behind a restricted NAT."))
		case stun.STUN_NAT_PORT_RESTRICTED:
			fmt.Println(fmt.Sprintf("We are behind a port restricted NAT."))
		case stun.STUN_NAT_NO_NAT:
			fmt.Println(fmt.Sprintf("We are not behind a NAT."))
		case stun.STUN_NAT_SYMETRIC_UDP_FIREWALL:
			fmt.Println(fmt.Sprintf("We are behind a symetric UDP firewall."))
	}
}



