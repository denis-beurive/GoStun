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
	"fmt"
	"github.com/denis-beurive/GoStun/src/tools"
	"net"
)

var client_initialized bool = false
var server_transport_address string

/* ------------------------------------------------------------------------------------------------ */
/* Return values for the discobery process.                                                         */
/* ------------------------------------------------------------------------------------------------ */

// This value indicates that an error occurred.
const STUN_NAT_ERROR = -1

// This value indicates that UDP is blocked.
const STUN_NAT_BLOCKED = 0

// This value indicates that the client can not determine the NAT's type.
const STUN_NAT_UNKNOWN = 1

// This value indicates that the client is behind a full cone NAT.
const STUN_NAT_FULL_CONE = 2

// This value indicates that the client is behind a symetric NAT.
const STUN_NAT_SYMETRIC = 3

// This value indicates that the client is behind a restricted NAT.
const STUN_NAT_RESTRICTED = 4

// This value indicates that the client is behind a port restricted NAT.
const STUN_NAT_PORT_RESTRICTED = 5

// This value indicates that the client is not behind a NAT.
const STUN_NAT_NO_NAT = 6

// This value indicates that the client is behind a symetric UDP firewall.
const STUN_NAT_SYMETRIC_UDP_FIREWALL = 7

/* ------------------------------------------------------------------------------------------------ */
/* Value types for the test functions.                                                              */
/* ------------------------------------------------------------------------------------------------ */

// This type contains the information returned by a request.
// This is the return value for the following functions:
// - ClientSendBinding
// - ClientSendChangeRequest
type requestResponse struct {
	// This flag indicates wether a response has been received or not.
	response bool
	// If a response has been received, then this value contains the response.
	packet StunPacket
	// The local transport address.
	// This value should is written: "IP:Port" (IPV4) or "[IP]:Port" (IPV6).
	transport_local string
	// Error detected wile waiting for a response.
	err error
}

// This type represents the specific information returned by test I.
type test1Info struct {
	// Did the server give a "change" address?
	changed_address_found bool
	// The "IP family" value of the attribute "CHANGED-ADDRESS".
	changed_address_family uint16
	// The "IP value" of the attribute "CHANGED-ADDRESS".
	changed_ip string
	// The "port numner value" of the attribute "CHANGED-ADDRESS".
	changed_port uint16
	// This flag indicates wether the local IP address id equal to the mapped one, or not.
	identical bool
}

// This type represents the specific information returned by test II.
type test2Info struct {
}

// This type represents the specific information returned by test III.
type test3Info struct {
}

// This type represents the information returned by a test.
// This is the return value for the following functions:
// - ClientTest1
// - ClientTest2
// - ClientTest3
type testResponse struct {
	// The response to the request.
	request requestResponse
	// Specific information for a given test. Type could be:
	// - test1Info
	// - test2Info
	// - test3Info
	extra interface{}
}

/* ------------------------------------------------------------------------------------------------ */
/* API                                                                                              */
/* ------------------------------------------------------------------------------------------------ */

// Initialize the information returned by a request.
func (v *requestResponse) init() {
	v.response = false
	v.err = nil
}

// This function opens a UDP connection.
//
// INPUT
// - in_server: transport address of the server.
//   This value should be written: "IP:Port" (IPV4) or "[IP]:Port" (IPV6).
func ClientInit(in_server string) {
	server_transport_address = in_server
	client_initialized = true
}

// This function sends a BINDING request.
//
// INPUT
// - in_destination_address: this string represents the transport address of the request's destination.
//   This value should be written: "IP:Port" (IPV4) or "[IP]:Port" (IPV6).
//   If the value of this parameter is nil, then the default server's transport address will be used.
//   Note: The default server's transport address is the one defined through the call to the function "ClientInit()".
//
// OUTPUT
// - The response.
// - The error flag.
func ClientSendBinding(in_destination_address *string) (requestResponse, error) {
	var attribute StunAttribute
	var err error
	var connection net.Conn
	var resp requestResponse
	var packet StunPacket
	var dest_address string

	packet = PacketCreate()
	resp.init()

	// Build the packet.
	packet.SetType(STUN_TYPE_BINDING_REQUEST)
	packet.SetId([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12})

	// Add The software attribute.
	attribute, err = AttributeCreateSoftware(&packet, "TestClient01")
	if nil != err {
		return resp, err
	}
	packet.AddAttribute(attribute)

	// Add the fingerprint attribute.
	attribute, err = AttributeCreateFingerprint(&packet)
	if nil != err {
		return resp, err
	}
	packet.AddAttribute(attribute)

	// Open a connection to the server.
	if nil != in_destination_address {
		dest_address = *in_destination_address
	} else {
		dest_address = server_transport_address
	}

	connection, err = net.Dial("udp", dest_address)
	if err != nil {
		return resp, err
	}
	resp.transport_local = connection.LocalAddr().String()

	// Send the packet.
	resp.packet, resp.response, resp.err = SendRequest(connection, packet)

	return resp, connection.Close()
}

// This function sends a CHANGE-REQUEST request.
//
// INPUT
// - in_change_ip: this flag indicates whether the "change IP flag" should be set or not.
//
// OUTPUT
// - The response.
// - The error flag.
func ClientSendChangeRequest(in_change_ip bool) (requestResponse, error) {
	var attribute StunAttribute
	var err error
	var connection net.Conn
	var resp requestResponse
	var packet StunPacket

	resp.init()
	packet = PacketCreate()

	// Build the packet.
	packet.SetType(STUN_TYPE_BINDING_REQUEST)
	packet.SetId([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12})

	// Add The software attribute
	attribute, err = AttributeCreateSoftware(&packet, "TestClient01")
	if nil != err {
		return resp, err
	}
	packet.AddAttribute(attribute)

	// Add The software attribute
	attribute, err = AttributeCreateChangeRequest(&packet, in_change_ip, true)
	if nil != err {
		return resp, err
	}
	packet.AddAttribute(attribute)

	// Add the fingerprint attribute.
	attribute, err = AttributeCreateFingerprint(&packet)
	if nil != err {
		return resp, err
	}
	packet.AddAttribute(attribute)

	// Open a connection to the server.
	connection, err = net.Dial("udp", server_transport_address)
	if err != nil {
		return resp, err
	}
	resp.transport_local = connection.LocalAddr().String()

	// Send the packet.
	resp.packet, resp.response, resp.err = SendRequest(connection, packet)

	return resp, connection.Close()
}

// Perform Test I.
// RFC 3489: In test I, the client sends a
//           STUN Binding Request to a server, without any flags set in the
//           CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute.
//           This causes the server to send the response back to the address and
//           port that the request came from.
//
// INPUT
// - in_destination_address: this string represents the transport address of the request's destination.
//   This value should be written: "IP:Port" (IPV4) or "[IP]:Port" (IPV6).
//   If the value of this parameter is nil, then the default server's transport address will be used.
//   Note: The default server's transport address is the one defined through the call to the function "ClientInit()".
//
// OUTPUT
// - The response.
// - The error flag.
func ClientTest1(in_destination_address *string) (testResponse, error) {
	var err, err_mapped error
	var ip_mapped, ip_xored_mapped string
	var family_mapped, family_xored_mapped, port_mapped, port_xored_mapped uint16
	var response testResponse
	var info test1Info
	var found bool

	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf("%s", "Test I\n"))
	}

	response.request, err = ClientSendBinding(in_destination_address)
	if nil != err {
		return response, err
	}
	if !response.request.response {
		return response, nil
	}

	// Extracts the mapped address and the XORED mapped address.
	// Note: Some STUN servers don't set the XORED mapped address (RFC 3489 does not define XORED mapped IP address).
	//       Therefore, we consider that no XORED mapped address is not an error.
	_ = family_mapped // Really not used
	found, family_mapped, ip_mapped, port_mapped, err = response.request.packet.GetMappedAddress()
	if (nil != err) || (!found) {
		return response, err
	}
	found, family_xored_mapped, ip_xored_mapped, port_xored_mapped, err = response.request.packet.GetXorMappedAddress()

	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf("% -25s: %s:%d", "Mapped address", ip_mapped, port_mapped))
		if nil == err_mapped && found {
			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("% -25s: %s:%d", "Xored mapped address", ip_xored_mapped, port_xored_mapped))
			}
		} else {
			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Xored mapped address", "No xored mapped address given"))
			}
		}
	}

	if (ip_mapped != ip_xored_mapped) && (found) {
		ip_mapped = ip_xored_mapped
		port_mapped = port_xored_mapped
		family_mapped = family_xored_mapped
	}

	ip_mapped, err = tools.MakeTransportAddress(ip_mapped, int(port_mapped))
	if nil != err {
		return response, err
	}

	// Extracts the transport address "CHANGED-ADDRESS".
	// Some servers don't set the attribute "CHANGED-ADDRESS".
	// So we consider that the lake of this attribute is not an error.
	info.changed_address_found, info.changed_address_family, info.changed_ip, info.changed_port, err = response.request.packet.GetChangedAddress()
	if nil != err {
		return response, err
	}

	// Compare local IP with mapped IP.
	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf("% -25s: %s", "Local address", response.request.transport_local))
	}
	info.identical = response.request.transport_local == ip_mapped
	response.extra = info

	return response, nil
}

// Perform Test II.
// RFC 3489: In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
//           from the CHANGE-REQUEST attribute set.
//
// OUTPUT
// - A boolean that indicates wether the client received a response or not.
// - The error flag.
func CientTest2() (testResponse, error) {
	var err error
	var r requestResponse
	var response testResponse
	var info test2Info

	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf("%s", "Test II.\n"))
	}
	r, err = ClientSendChangeRequest(true)
	response.request = r
	response.extra = info
	if nil != err {
		return response, err
	}
	return response, nil
}

// Perform Test III.
// RFC 3489: In test III, the client sends a Binding Request with only the "change port" flag set.
//
// OUTPUT
// - A boolean that indicates wether the client received a response or not.
// - The error flag.
func CientTest3() (testResponse, error) {
	var err error
	var r requestResponse
	var response testResponse
	var info test2Info

	if verbosity > 0 {
		tools.AddText(output, fmt.Sprintf("%s", "Test III.\n"))
	}
	r, err = ClientSendChangeRequest(false)
	response.request = r
	response.extra = info
	if nil != err {
		return response, err
	}
	return response, nil
}

// Perform the discovery process.
// See RFC 3489, section "Discovery Process".
//
// OUTPUT
// - The type of NAT we are behind from.
// - The error flag.
func ClientDiscover() (int, error) {
	var err error
	var changer_transport string
	var test1_response, test2_response, test3_response testResponse

	// RFC 3489: The client begins by initiating test I.  If this test yields no
	// response, the client knows right away that it is not capable of UDP
	// connectivity.  If the test produces a response, the client examines
	// the MAPPED-ADDRESS attribute.  If this address and port are the same
	// as the local IP address and port of the socket used to send the
	// request, the client knows that it is not natted.  It executes test II.

	/// ----------
	/// TEST I (a)
	/// ----------

	test1_response, err = ClientTest1(nil)

	if nil != err {
		return STUN_NAT_ERROR, err
	}
	if !test1_response.request.response {
		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s%s", "Result:", "Got no response for test I."))
			tools.AddText(output, fmt.Sprintf("% -25s%s", "Conclusion:", "UDP is blocked."))
		}
		return STUN_NAT_BLOCKED, err
	}

	// Save "changed transport address" for later test.
	// Please note that some servers don't set this attribute.
	if test1_response.extra.(test1Info).changed_address_found {
		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Change IP", test1_response.extra.(test1Info).changed_ip))
			tools.AddText(output, fmt.Sprintf("% -25s: %d", "Change port", int(test1_response.extra.(test1Info).changed_port)))
		}
		changer_transport, err = tools.MakeTransportAddress(test1_response.extra.(test1Info).changed_ip, int(test1_response.extra.(test1Info).changed_port))
		if nil != err {
			return STUN_NAT_ERROR, err
		}
	} else {
		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "The response does not contain any \"changed\" address."))
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "The only thing we can say is that we are behind a NAT.\n"))
		}
		return STUN_NAT_UNKNOWN, nil
	}

	if !test1_response.extra.(test1Info).identical { // Test I (a): The local transport address is different than the mapped transport address.

		// RFC 3489: In the event that the IP address and port of the socket did not match
		// the MAPPED-ADDRESS attribute in the response to test I, the client
		// knows that it is behind a NAT. It performs test II.

		/// -----------
		/// TEST II (a)
		/// -----------

		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test I. Test I is not OK."))
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a NAT.\n"))
		}

		test2_response, err = CientTest2()
		if nil != err {
			return STUN_NAT_ERROR, err
		}
		if !test2_response.request.response { // Test II (a): We did not receive any valid response from the server.

			// RFC 3489:  If no response is received, it performs test I again, but this time,
			// does so to the address and port from the CHANGED-ADDRESS attribute
			// from the response to test I.

			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got no response for test II. Test II is not OK."))
				tools.AddText(output, fmt.Sprintf("% -25s: %s \"%s\"\n", "Conclusion", "Perform Test I again. This time, server's transport address is", changer_transport))
			}

			/// ----------
			/// TEST I (b)
			/// ----------

			test1_response, err = ClientTest1(&changer_transport)
			if nil != err {
				return STUN_NAT_ERROR, err
			}
			if !test1_response.request.response {
				// No response from the server. This should not happend.
				if verbosity > 0 {
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got no response for test I. This is unexpected!"))
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "The only thing we can say is that we are behind a NAT.\n"))
				}
				return STUN_NAT_UNKNOWN, nil
			}

			if !test1_response.extra.(test1Info).identical { // Test I (b)
				if verbosity > 0 {
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test I. Test I is not OK."))
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a symetric NAT.\n"))
				}
				return STUN_NAT_SYMETRIC, nil
			} else { // Test I (b)

				if verbosity > 0 {
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test I. Test I is OK.\n"))
					tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "Perform Test III.\n"))
				}

				/// --------
				/// TEST III
				/// --------

				test3_response, err = CientTest3()
				if nil != err {
					return STUN_NAT_ERROR, err
				}
				if !test3_response.request.response {
					if verbosity > 0 {
						tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got no response for test III."))
						tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a \"port sestricted\" NAT.\n"))
					}
					return STUN_NAT_PORT_RESTRICTED, nil
				} else {
					if verbosity > 0 {
						tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test III."))
						tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a \"restricted\" NAT.\n"))
					}
					return STUN_NAT_RESTRICTED, nil
				}

				// End of branch.
			}
		} else { // TEST II (a) : We received a valid response from the server.

			// RFC 3489: If a response is received, the client knows that it is behind a \"full-cone\" NAT.

			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Test II is OK."))
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a \"full cone\" NAT.\n"))
			}
			return STUN_NAT_FULL_CONE, nil
		}

		return 0, nil
	} else { // Test I (a): The local transport address is identical to the mapped transport address.

		// RFC 3489: If this address and port are the same
		// as the local IP address and port of the socket used to send the
		// request, the client knows that it is not natted. It executes test II.

		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test 1. Test I is OK. Addresses are the same.\n"))
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are *not* behind a NAT."))
		}

		/// -----------
		/// TEST II (b)
		/// -----------

		// If a response is received, the client knows that it has open access
		// to the Internet (or, at least, its behind a firewall that behaves
		// like a full-cone NAT, but without the translation).  If no response
		// is received, the client knows its behind a symmetric UDP firewall.

		test2_response, err = CientTest2()
		if nil != err {
			return STUN_NAT_ERROR, err
		}
		if test2_response.request.response { //
			if verbosity > 0 {
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got a response for test II.\n"))
				tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are *not* behind a NAT."))
			}
			return STUN_NAT_NO_NAT, nil
		}

		if verbosity > 0 {
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Result", "Got no response for test II.\n"))
			tools.AddText(output, fmt.Sprintf("% -25s: %s", "Conclusion", "We are behind a symmetric UDP firewall."))
		}
		return STUN_NAT_SYMETRIC_UDP_FIREWALL, nil
	}

	return 2, nil
}
