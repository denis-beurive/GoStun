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

import "encoding/binary"
import "unicode/utf8"
import "hash/crc32"
import "bytes"
import "tools"
import "errors"
import "fmt"

// IP family is IPV4
const STUN_ATTRIBUT_FAMILY_IPV4   = 0x01

// IP family is IPV6
const STUN_ATTRIBUT_FAMILY_IPV6   = 0x02

/* ------------------------------------------------------------------------------------------------ */
/* Attributes' types.                                                                               */
/*                                                                                                  */
/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
/* Note: Value STUN_ATTRIBUT_XOR_MAPPED_ADDRESS_EXP is not mentioned in the above document.         */
/*       But it is used by servers.                                                                 */
/* ------------------------------------------------------------------------------------------------ */

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_MAPPED_ADDRESS 				= 0x0001

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_RESPONSE_ADDRESS    		= 0x0002

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CHANGE_REQUEST				= 0x0003

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_SOURCE_ADDRESS				= 0x0004

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CHANGED_ADDRESS				= 0x0005

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_USERNAME					= 0x0006

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_PASSWORD					= 0x0007

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_MESSAGE_INTEGRITY			= 0x0008

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_ERROR_CODE					= 0x0009

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_UNKNOWN_ATTRIBUTES			= 0x000A

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_REFLECTED_FROM				= 0x000B

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CHANNEL_NUMBER				= 0x000C

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_LIFETIME					= 0x000D

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_BANDWIDTH					= 0x0010

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_XOR_PEER_ADDRESS			= 0x0012

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_DATA						= 0x0013

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_REALM						= 0x0014

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_NONCE						= 0x0015

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_XOR_RELAYED_ADDRESS 		= 0x0016

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_REQUESTED_ADDRESS_FAMILY	= 0x0017

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_EVEN_PORT					= 0x0018

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_REQUESTED_TRANSPORT			= 0x0019

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_DONT_FRAGMENT				= 0x001A

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_XOR_MAPPED_ADDRESS			= 0x0020

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_TIMER_VAL					= 0x0021

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_RESERVATION_TOKEN			= 0x0022

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_PRIORITY					= 0x0024

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_USE_CANDIDATE				= 0x0025

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_PADDING						= 0x0026

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_RESPONSE_PORT				= 0x0027

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CONNECTION_ID				= 0x002A

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_XOR_MAPPED_ADDRESS_EXP		= 0x8020

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_SOFTWARE					= 0x8022

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_ALTERNATE_SERVER			= 0x8023

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CACHE_TIMEOUT				= 0x8027

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_FINGERPRINT					= 0x8028

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_ICE_CONTROLLED				= 0x8029

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_ICE_CONTROLLING				= 0x802A

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_RESPONSE_ORIGIN				= 0x802B

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_OTHER_ADDRESS				= 0x802C

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_ECN_CHECK_STUN				= 0x802D

// See: Session Traversal Utilities for NAT (STUN) Parameters
//      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
const STUN_ATTRIBUT_CISCO_STUN_FLOWDATA			= 0xC000

// This map associates an attribute's value to a attribute's name.
// Note: This following code was generated using a Perl script, to avoid typos. See directory "extra" (script consts2map.pl).
var attribute_names = map[uint16] string {
	STUN_ATTRIBUT_MAPPED_ADDRESS:                      "MAPPED_ADDRESS",
	STUN_ATTRIBUT_RESPONSE_ADDRESS:                    "RESPONSE_ADDRESS",
	STUN_ATTRIBUT_CHANGE_REQUEST:                      "CHANGE_REQUEST",
	STUN_ATTRIBUT_SOURCE_ADDRESS:                      "SOURCE_ADDRESS",
	STUN_ATTRIBUT_CHANGED_ADDRESS:                     "CHANGED_ADDRESS",
	STUN_ATTRIBUT_USERNAME:                            "USERNAME",
	STUN_ATTRIBUT_PASSWORD:                            "PASSWORD",
	STUN_ATTRIBUT_MESSAGE_INTEGRITY:                   "MESSAGE_INTEGRITY",
	STUN_ATTRIBUT_ERROR_CODE:                          "ERROR_CODE",
	STUN_ATTRIBUT_UNKNOWN_ATTRIBUTES:                  "UNKNOWN_ATTRIBUTES",
	STUN_ATTRIBUT_REFLECTED_FROM:                      "REFLECTED_FROM",
	STUN_ATTRIBUT_CHANNEL_NUMBER:                      "CHANNEL_NUMBER",
	STUN_ATTRIBUT_LIFETIME:                            "LIFETIME",
	STUN_ATTRIBUT_BANDWIDTH:                           "BANDWIDTH",
	STUN_ATTRIBUT_XOR_PEER_ADDRESS:                    "XOR_PEER_ADDRESS",
	STUN_ATTRIBUT_DATA:                                "DATA",
	STUN_ATTRIBUT_REALM:                               "REALM",
	STUN_ATTRIBUT_NONCE:                               "NONCE",
	STUN_ATTRIBUT_XOR_RELAYED_ADDRESS:                 "XOR_RELAYED_ADDRESS",
	STUN_ATTRIBUT_REQUESTED_ADDRESS_FAMILY:            "REQUESTED_ADDRESS_FAMILY",
	STUN_ATTRIBUT_EVEN_PORT:                           "EVEN_PORT",
	STUN_ATTRIBUT_REQUESTED_TRANSPORT:                 "REQUESTED_TRANSPORT",
	STUN_ATTRIBUT_DONT_FRAGMENT:                       "DONT_FRAGMENT",
	STUN_ATTRIBUT_XOR_MAPPED_ADDRESS:                  "XOR_MAPPED_ADDRESS",
	STUN_ATTRIBUT_TIMER_VAL:                           "TIMER_VAL",
	STUN_ATTRIBUT_RESERVATION_TOKEN:                   "RESERVATION_TOKEN",
	STUN_ATTRIBUT_PRIORITY:                            "PRIORITY",
	STUN_ATTRIBUT_USE_CANDIDATE:                       "USE_CANDIDATE",
	STUN_ATTRIBUT_PADDING:                             "PADDING",
	STUN_ATTRIBUT_RESPONSE_PORT:                       "RESPONSE_PORT",
	STUN_ATTRIBUT_CONNECTION_ID:                       "CONNECTION_ID",
	STUN_ATTRIBUT_XOR_MAPPED_ADDRESS_EXP:			   "XOR_MAPPED_ADDRESS",
	STUN_ATTRIBUT_SOFTWARE:                            "SOFTWARE",
	STUN_ATTRIBUT_ALTERNATE_SERVER:                    "ALTERNATE_SERVER",
	STUN_ATTRIBUT_CACHE_TIMEOUT:                       "CACHE_TIMEOUT",
	STUN_ATTRIBUT_FINGERPRINT:                         "FINGERPRINT",
	STUN_ATTRIBUT_ICE_CONTROLLED:                      "ICE_CONTROLLED",
	STUN_ATTRIBUT_ICE_CONTROLLING:                     "ICE_CONTROLLING",
	STUN_ATTRIBUT_RESPONSE_ORIGIN:                     "RESPONSE_ORIGIN",
	STUN_ATTRIBUT_OTHER_ADDRESS:                       "OTHER_ADDRESS",
	STUN_ATTRIBUT_ECN_CHECK_STUN:                      "ECN_CHECK_STUN",
	STUN_ATTRIBUT_CISCO_STUN_FLOWDATA:                 "CISCO_STUN_FLOWDATA",
}

// This structure represents a message's attribute of a STUM message.
type StunAttribute struct {
	// The attribute's type (constant STUN_ATTRIBUT_...).
	Type		uint16		// 16 bits
	
	// The length of the attribute.
	// RFC 5389: The value in the length field MUST contain the length of the Value
    //           part of the attribute, prior to padding, measured in bytes.  Since
    //           STUN aligns attributes on 32-bit boundaries, attributes whose content
    //           is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
    //           padding so that its value contains a multiple of 4 bytes.  The
    //           padding bits are ignored, and may be any value.
    //
    // **BUT** RFC 5389 says that the **real** length must be a multiple of 4! (no padding)
	Length		uint16		// 16 bits
	
	// The attribute's value.
	Value		[]byte		// variable number of bytes
	
	// The packet which the attribute belongs to.
	Packet		*StunPacket	// the packet that contains this attribute
}

/* ------------------------------------------------------------------------------------------------ */
/* Create                                                                                           */      
/*                                                                                                  */
/* NOTE: http://code.google.com/p/go-idn/                                                           */
/* ------------------------------------------------------------------------------------------------ */

// Create a message's attribute.
//
// INPUT
// - in_type: attribute's type.
// - in_value: attribute's value.
// - in_packet: pointer to the packet that contains the attribute.
//
// OUTPUT
// - The new attribute.
// - The error flag.
func AttributeCreate(in_type uint16, in_value []byte, in_packet *StunPacket) (StunAttribute, error) {
	var a StunAttribute
	
	if (0 != len(in_value) % 4) && (rfc == STUN_RFC_3489) {
		return a, errors.New("STUN is configured to be compliant with RFC 3489! Value's length must be a multiple of 4 bytes!")
	}
	
	padded   := __padding(in_value)
	a.Type   =  in_type
	a.Value  =  make([]byte, len(padded), len(padded))

	if (len(in_value) > 65535) { return a, errors.New(fmt.Sprintf("Can not create new attribute: attribute's value is too long (%d bytes)", len(in_value))) }
	a.Length = uint16(len(in_value))
	
	// fmt.Println(fmt.Sprintf("Create attribute with: % x (%d *real* bytes)", padded, a.Length))
	
	copy(a.Value, padded)
	a.Packet = in_packet
	return a, nil
}

// This function creates a "FINGERPRINT" attribute.
// See http://golang.org/src/pkg/hash/crc32/crc32.go
//
// INPUT
// - in_packet: Pointer to the STUN packet that is used to calculate the fingerprint.
//
// OUTPUT
// - The STUN's attribute.
// - The error flag.
//
// WARNING
// The FINGERPRINT attribute should be the last attribute of the STUN packet.
func AttributeCreateFingerprint(in_packet *StunPacket) (StunAttribute, error) {
	var err error
	var res StunAttribute
	buf := new(bytes.Buffer)

    crc := __stunCrc32(in_packet.ToBytes())
	
	err = binary.Write(buf, binary.BigEndian, crc)
	if (nil != err) { panic("Internal error"); }

	// Note: the value is 4 bytes long.
	res, err = AttributeCreate(STUN_ATTRIBUT_FINGERPRINT, buf.Bytes(), in_packet)
	if (nil != err) { return res, err }
	
	return res, nil
}

// This function creates a "SOFTWARE" attribute.
//
// INPUT
// - in_packet: pointer to the STUN packet.
// - in_name: name of the software.
//
// OUTPUT
// - The STUN's attribute.
// - The error flag.
func AttributeCreateSoftware(in_packet *StunPacket, in_name string) (StunAttribute, error) {
	var err error
	var res StunAttribute
	name := []byte(in_name)
	
	if (len(name) > 763) {
		return res, errors.New("Software's name if too long (more than 763 bytes!)")
	}
	
	res, err = AttributeCreate(STUN_ATTRIBUT_SOFTWARE, name, in_packet)
	if (nil != err) { return res, err }
	return res, nil
}

// This function creates a "CHANGE RESQUEST" attribute.
//
// INPUT
// - in_packet: pointer to the STUN packet.
// - in_ip: shall we change the IP address?
// - in_port: shall we change the port number?
//
// OUTPUT
// - The STUN's attribute.
// - The error flag.
func AttributeCreateChangeRequest(in_packet *StunPacket, in_ip bool, in_port bool) (StunAttribute, error) {
	var err error
	var res StunAttribute
	var value []byte = make([]byte, 4, 4)
	
	// RFC 3489: The CHANGE-REQUEST attribute is used by the client to request that
   	// the server use a different address and/or port when sending the
    // response.  The attribute is 32 bits long, although only two bits (A
    // and B) are used.
    if (in_ip)   { value[3] = value[3] | 0x04 } // b:0100
    if (in_port) { value[3] = value[3] | 0x02 } // b:0010
	
	res, err = AttributeCreate(STUN_ATTRIBUT_CHANGE_REQUEST, value, in_packet)
	if (nil != err) { return res, err }
	return res, nil
}

/* ------------------------------------------------------------------------------------------------ */
/* Get                                                                                              */
/* ------------------------------------------------------------------------------------------------ */

// Given an attribute that represents a "mapped" address, this function returns the transport address.
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The error flag.
func (v *StunAttribute) AttributeGetMappedAddress() (uint16, string, uint16, error) {
	return v.__getAddress()
}

// Given an attribute that represents a "source" address, this function returns the transport address.
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The error flag.
func (v *StunAttribute) AttributeGetSourceAddress() (uint16, string, uint16, error) {
	return v.__getAddress()
}

// Given an attribute that represents a "changed" address, this function returns the transport address.
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The error flag.
func (v *StunAttribute) AttributeGetChangeedAddress() (uint16, string, uint16, error) {
	return v.__getAddress()
}

// Given an attribute that represents a "XOR mapped" address, this function returns the transport address.
// See http://www.nexcom.fr/2012/06/stun-la-base/
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The XORED IP address (should be equal to the mapped address).
// - The XORED port (should be equal to the mapped port).
// - The error flag.
func (v *StunAttribute) AttributeGetXorMappedAddress() (uint16, string, uint16, string, uint16, error) {
	var family, port uint16
	var ip_string string
	var xored_ip_string string
	var err error
	var cookie []byte = []byte{ 0x21, 0x12, 0xA4, 0x42 } // 0x2112A442
	var xored_ip []byte = make([]byte, 0, 16)
	var xored_port uint16
	
	err = binary.Read(bytes.NewBuffer(v.Value[0:2]), binary.BigEndian, &family)
	if (nil != err) { return 0, "", 0, "", 0, err }
	
	if ((STUN_ATTRIBUT_FAMILY_IPV4 != family) && (STUN_ATTRIBUT_FAMILY_IPV6 != family)) {
		return 0, "", 0, "", 0, errors.New(fmt.Sprintf("Invalid address' family: 0x%02x", family))
	}
	
	err = binary.Read(bytes.NewBuffer(v.Value[2:4]), binary.BigEndian, &port)
	if (nil != err) { return family, "", 0, "", 0, err }
	
	if (STUN_ATTRIBUT_FAMILY_IPV4 == family) { // IPV4
		if (len(v.Value[4:]) != 4) {
			return 0, "", 0, "", 0, errors.New(fmt.Sprintf("Invalid IPV4 address: % x", v.Value[4:]))
		}
		for i := 0; i<4 ; i++ {
			xored_ip = append(xored_ip, v.Value[i+4] ^ cookie[i])
		}
	} else { // IPV6
		var long_magic []byte = make([]byte, 0, 16)
		
		if (len(v.Value[4:]) != 16) {
			return 0, "", 0, "", 0, errors.New(fmt.Sprintf("Invalid IPV6 address: % x", v.Value[4:]))
		}
		long_magic = append(long_magic, cookie...)
		long_magic = append(long_magic, v.Packet.id[0:12]...)
		for i := 0; i<16; i++ {
			xored_ip = append(xored_ip, v.Value[i+4] ^ cookie[i])
		}
	}
	
	// Calculate the values to return.
	// - family
	// - ip_string
	// - port
	// - xored_ip_string
	// - xored_port
	
	ip_string, err = tools.BytesToIp(v.Value[4:])
	if (nil != err) { return 0, "", 0, "", 0, err }
	
	xored_ip_string, err = tools.BytesToIp(xored_ip)
	if (nil != err) { return 0, "", 0, "", 0, err }
	
	xored_port = port ^ 0x2112
	
	return family, ip_string, port, xored_ip_string, xored_port, nil
}

// Given an attribute that represents a "SOFTWARE" attribute, this function returns the name of the software.
//
// OUTPUT
// - The name of the software.
func (v *StunAttribute) AttributeGetSoftware() (string) {
	for i:=0; i<len(v.Value); i++ {
		r, size := utf8.DecodeRune(v.Value[i:])
		if (utf8.RuneError == r) {
			return "Can not convert this list of bytes into a string. It is not UTF8 encoded."
		}
		i += size - 1
	}
	return string(v.Value)
}

// This function returns a 32-bit integer that represents the fingerprint.
//
// OUTPUT
// - The fingerprint.
// - The error flag.
func (v *StunAttribute) AttributeGetFingerprint() (uint32, error) {
	var crc uint32
	
	if (4 != len(v.Value)) {
		return 0xFFFFFFFF, errors.New(fmt.Sprintf("Invalid fingerprint (% x)", v.Value))
	}
	
	err := binary.Read(bytes.NewBuffer(v.Value), binary.BigEndian, &crc)
	if (nil != err) { return 0xFFFFFFFF, err }
	return crc, nil
}

// This function returns the value of an attribute which type is "REQUEST_CHANGE".
//
// OUPUT
// - A boolean value that indicates whether IP change is requested or not.
// - A boolean value that indicates whether port number change is requested or not.
// - The error flag.
func (v *StunAttribute) AttributeGetChangeRequest() (bool, bool, error) {
	if (4 != len(v.Value)) {
		return false, false, errors.New(fmt.Sprintf("Invalid change requested value (% x)", v.Value))
	}
	return (0x04 | v.Value[3]) != 0, (0x02 | v.Value[3]) != 0, nil
}


/* ------------------------------------------------------------------------------------------------ */
/* Export                                                                                           */
/* ------------------------------------------------------------------------------------------------ */

// This function returns a textual representation of the attribute, if possible.
//
// OUTPUT
// - The function returns a textual representation of the attribute, if possible.
// - The flag that indicates whether the function can generate a textual representation of the attribute or not.
func (v *StunAttribute) String() (string, bool) {

	if (STUN_ATTRIBUT_MAPPED_ADDRESS  == v.Type ||
	    STUN_ATTRIBUT_SOURCE_ADDRESS  == v.Type ||
	    STUN_ATTRIBUT_CHANGED_ADDRESS == v.Type) {
		family, ip, port, err := v.__getAddress()
		if (nil != err) { return "This attribute is not valid.", true }
		if (0x01 == family) {
			return fmt.Sprintf("IPV4: %s:%d", ip, port), true
		} else {
			return fmt.Sprintf("IPV6: [%s]:%d", ip, port), true
		}
	}
	
	if (STUN_ATTRIBUT_XOR_MAPPED_ADDRESS     == v.Type ||
	    STUN_ATTRIBUT_XOR_MAPPED_ADDRESS_EXP == v.Type) {
		family, ip, port, xored_ip, xored_port, err := v.AttributeGetXorMappedAddress()
		if (nil != err) { return "This attribute is not valid.", true }
		if (0x01 == family) {
			return fmt.Sprintf("IPV4: %s:%d => %s:%d", ip, port, xored_ip, xored_port), true
		} else {
			return fmt.Sprintf("IPV6: [%s]:%d => [%s]:%d", ip, port, xored_ip, xored_port), true
		}
	}
	
	if (STUN_ATTRIBUT_SOFTWARE == v.Type) {
		return v.AttributeGetSoftware(), true
	}
	
	if (STUN_ATTRIBUT_FINGERPRINT == v.Type) {
		crc, err := v.AttributeGetFingerprint()
		if (nil != err) {
			return fmt.Sprintf("This attribute is not valid: %s", err), true
		}
		return fmt.Sprintf("0x%08x", crc), true
	}
	
	if (STUN_ATTRIBUT_CHANGE_REQUEST == v.Type) {
		ip, port, err := v.AttributeGetChangeRequest()
		if (nil != err) {
			return fmt.Sprintf("This attribute is not valid: %s", err), true
		}
		var ips, ports string
		if (ip) { ips   = "YES" } else { ips = "NO" }
		if (port) { ports = "YES" } else { ports = "NO" }
		return fmt.Sprintf("Change IP: %s Change port: %s", ips, ports), true
	}
	
	return "There is no available representation.", false
}

/* ------------------------------------------------------------------------------------------------ */
/* Privates                                                                                         */
/* ------------------------------------------------------------------------------------------------ */

// Given an attribute that represents an address, this function returns the transport address (IP and port number).
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The error flag.
func (v *StunAttribute) __getAddress() (uint16, string, uint16, error) {
	var family, port uint16
	var ip string
	var err error
	
	err = binary.Read(bytes.NewBuffer(v.Value[0:2]), binary.BigEndian, &family)
	if (nil != err) { return 0, "", 0, err }
	
	err = binary.Read(bytes.NewBuffer(v.Value[2:4]), binary.BigEndian, &port)
	if (nil != err) { return family, "", 0, err }
	
	ip, err = tools.BytesToIp(v.Value[4:])
	if (nil != err) { return family, "", port, errors.New("Invalid IP family.") }
		
	return family, ip, port, nil
}

// The function calculates the STUN's fingerprint.
// RFC 5389: The value of the attribute is computed as the CRC-32 of the STUN message
//           up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
//           the 32-bit value 0x5354554e (the XOR helps in cases where an
//           application packet is also using CRC-32 in it).
//
// INPUT
// - in_byte: the list of bytes.
//
// OUTPUT
// - The fingerprint.
//
// NOTE
// Test: http://www.armware.dk/RFC/rfc/rfc5769.html
func __stunCrc32(in_byte []byte) (uint32) {
	return crc32.ChecksumIEEE(in_byte) ^ 0x5354554e
}

// This function adds zeros prior to a slice of bytes. The length of the resulting slice is a multiple of 4.
//
// INPUT
// - in_byte: the slice of bytes to padd.
//
// OUTPUT
// - The padded slice.
func __padding(in_byte []byte) []byte {
	rest := len(in_byte) % 4
	if (0 == rest) { return in_byte }
	padding := make([]byte, 4-rest, 4-rest)  // all zeros
	return append(in_byte, padding...)
}

// Given a value, this function calculates the next multiple of 4.
//
// INPUT
// - in_lentgh: the value.
//
// OUPUT
// - The next multiple of 4.
func __nextBoundary(in_length uint16) uint16 {
	rest := in_length % 4
	if (0 == rest) { return in_length }
	return in_length + 4 - rest
}



