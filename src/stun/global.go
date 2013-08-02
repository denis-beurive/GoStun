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

package stun

import (
	"errors"
	"fmt"
	"github.com/denis-beurive/GoStun/src/tools"
	"net"
	"strings"
	"time"
)

// Verbosity level for the STUN package.
var verbosity int = 0

// Buffer used to store the package's output, if buffering is required.
var output *[]string = nil

// This function activates the output.
//
// INPUT
// - in_verbosity: verbosity level.
// - out_verbose: pointer to a slice of strings that will be used to store the output messages.
//   If this parameter is nil, then the message will be printed in through the standard output.
func ActivateOutput(in_vebosity int, out_verbose *[]string) {
	verbosity = in_vebosity
	output = out_verbose
}

// This function sends a given request and returns the received packet.
//
// INPUT
// - in_connexion: connexion to use.
// - in_request: the request to send.
//
// OUTPUT
// - The receive STUN packet.
// - A flag that indicates whether the client received a response or not.
//   + true: the client received a response.
//   + false: the client did not receive any response
// - The error flag.
func SendRequest(in_connexion net.Conn, in_request StunPacket) (StunPacket, bool, error) {
	var rcv_packet StunPacket
	var request_timeout int = 100
	var retries_count int = 0

	sent := false

	for {
		var err error
		var count int
		var b []byte = make([]byte, 1000, 1000)

		// Dump the packet.
		if (verbosity > 0) && !sent {
			tools.AddText(output, fmt.Sprintf("Sending REQUEST to \"%s\"\n\n%s\n", in_connexion.RemoteAddr(), Bytes2String(in_request.ToBytes(), 4)))
			tools.AddText(output, fmt.Sprintf("%s\n", in_request.String(4)))
			sent = true
		}

		// Send the packet.
		count, err = in_connexion.Write(in_request.ToBytes())
		if err != nil {
			return rcv_packet, false, errors.New(fmt.Sprintf("Can not send STUN UDP packet to server: %s", err))
		}
		if len(in_request.ToBytes()) != count {
			return rcv_packet, false, errors.New(fmt.Sprintf("Can not send STUN UDP packet to server: The number of bytes sent is not valid."))
		}

		// RFC 3489: Wait for a response.
		// Clients SHOULD retransmit the request starting with an interval of 100ms, doubling
		// every retransmit until the interval reaches 1.6s.  Retransmissions
		// continue with intervals of 1.6s until a response is received, or a
		// total of 9 requests have been sent.
		in_connexion.SetReadDeadline(time.Now().Add(time.Duration(request_timeout) * time.Millisecond))
		if request_timeout < 1600 {
			request_timeout *= 2
		} else {
			retries_count++
		}

		// Wait for a response.
		count, err = in_connexion.Read(b)
		if err != nil {
			if err.(net.Error).Timeout() { // See http://golang.org/src/pkg/net/timeout_test.go?h=Timeout%28%29
				if retries_count >= 9 {
					break
				}
				if verbosity > 0 {
					tools.AddText(output, fmt.Sprintf("%sTimeout (%04d ms) exceeded, retry...", strings.Repeat(" ", 4), request_timeout))
				}
				continue
			}
			return rcv_packet, false, errors.New(fmt.Sprintf("Error while reading packet: %s", err))
		}

		// For nice output.
		if (verbosity > 0) && (retries_count > 0) {
			tools.AddText(output, "\n")
		}

		// Build the packet from the list of bytes.
		rcv_packet, err = FromBytes(b[0:count])
		if nil != err {
			// The packet is not valid.
			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("%sThe received packet is not valid. Continue.", strings.Repeat(" ", 4)))
			}
			continue
		}
		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("Received\n\n%s\n", Bytes2String(rcv_packet.ToBytes(), 4)))
			tools.AddText(output, fmt.Sprintf("%s\n", rcv_packet.String(4)))
		}

		// OK, a valid response has been received.
		return rcv_packet, true, nil
	}

	// No valid packet has been received.
	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf(""))
	}
	return rcv_packet, false, nil
}
