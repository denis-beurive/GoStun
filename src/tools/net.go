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

package tools

import "strings"
import "errors"
import "fmt"
import "strconv"
import "encoding/binary"
import "bytes"
import "regexp"

// This function extracts the IP address and the port number from a string that represents a transport address.
// The string should be "IP:port".
//
// INPUT
// - in_inet: the transport address.
//            The given transport address could be IPV4 or IPV6.
//            Example for IPV4: "192.168.0.1:1456"
//            Example for IPV6: "[2001:0DB8:0000:85a3:0000:0000:ac1f:8001]:16547"
//
// OUTPUT
// - The IP address.
// - The port number.
// - The error flag.
func InetSplit(in_inet string) (out_ip string, out_port int, out_err error) {
	var err error
	var port int
	var data []string
	var ipv4, ipv6 *regexp.Regexp

	ipv4, err = regexp.Compile("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})$")
	if nil != err {
		panic("Internal error.")
	}

	ipv6, err = regexp.Compile("^\\[([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})\\]:(\\d{1,5})$")
	if nil != err {
		panic("Internal error.")
	}

	// Is it IPV4 or IPV6?
	data = ipv4.FindStringSubmatch(in_inet)
	if nil == data {
		data = ipv6.FindStringSubmatch(in_inet)
		if nil == data {
			return "", -1, errors.New(fmt.Sprintf("Invalid IP address \"%s\". Can not determine the address' family.", in_inet))
		}
	}

	port, err = strconv.Atoi(data[2])
	if nil != err {
		return "", -1, errors.New(fmt.Sprintf("Invalid INET address \"%s\". The port number is not valid (\"%s\"). It is not an integer.", in_inet, data[2]))
	}
	return data[1], port, nil
}

// This function converts an IP address into a list of bytes.
//
// INPUT
// - in_ip: IP address (IPV4 or IPV6).
//          Example for IPV4: "192.168.0.1" will return []byte{12, 13, 14, 15}
//          Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF" will return []byte{ 0x00, 0x11, 0x22, 0x33, ... }
//
// OUTPUT
// - The list of bytes.
// - The error flag.
func IpToBytes(in_ip string) (out_bytes []byte, out_err error) {
	var err error
	var dot, max uint64
	var length int
	var res []byte = make([]byte, 0, 16)
	var data []string

	// Try IPV4.
	data = strings.Split(in_ip, ".")
	if 1 == len(data) { // Try IPV6
		data = strings.Split(in_ip, ":")
	}

	length = len(data)
	if (4 != length) && (8 != length) {
		return nil, errors.New(fmt.Sprintf("Invalid IP address \"%s\".", in_ip))
	}
	if 4 == length {
		max = 255
	} else {
		max = 65535
	}

	for i := 0; i < length; i++ {
		buf := new(bytes.Buffer)

		if 4 == length { // IPV4
			dot, err = strconv.ParseUint(data[i], 10, 64)
		} else { // IPV6
			dot, err = strconv.ParseUint(data[i], 16, 64)
		}

		if nil != err {
			return nil, errors.New(fmt.Sprintf("Invalid IP address \"%s\".", in_ip))
		}
		if (dot > max) || (dot < 0) {
			return nil, errors.New(fmt.Sprintf("Invalid IP address \"%s\".", in_ip))
		}
		err = binary.Write(buf, binary.BigEndian, uint16(dot))
		if nil != err {
			panic("Internal error")
		}

		if 4 == length { // IPV4
			res = append(res, buf.Bytes()[1])
		} else { // IPV6
			res = append(res, buf.Bytes()...)
		}
	}

	return res, nil
}

// This function converts a list of bytes into a string that represents an IP address.
//
// INPUT
// - in_bytes: list of bytes to convert.
//
// OUTPUT
// - The IP address. This can be an IPV4 or IPV6.
// - The error flag.
func BytesToIp(in_bytes []byte) (string, error) {
	var ip []string = make([]string, 0, 8)
	var family int = 0
	var res string

	if 4 == len(in_bytes) {
		family = 4
	}
	if 16 == len(in_bytes) {
		family = 6
	}
	if 0 == family {
		return "", errors.New("Invalid list of bytes: this does not represent an IP!")
	}

	if 4 == family {
		for i := range in_bytes {
			ip = append(ip, strconv.Itoa(int(in_bytes[i])))
		}
		res = strings.Join(ip, ".")
	}

	if 6 == family {
		var err error
		for i := 0; i < 8; i++ {
			var dot uint16
			err = binary.Read(bytes.NewBuffer(in_bytes[i*2:(i+1)*2]), binary.BigEndian, &dot)
			if nil != err {
				return "", err
			}
			ip = append(ip, fmt.Sprintf("%04x", dot))
		}
		res = strings.Join(ip, ":")
	}

	return res, nil
}

// Given an IP address and a port number, this function creates a transport address.
//
// INPUT
// - in_ip: IP address.
// - in_port: port number.
//
// OUTPUT
// - The transport address.
// - The error flag.
func MakeTransportAddress(in_ip string, in_port int) (string, error) {
	var ipv4, ipv6 *regexp.Regexp
	var err error

	ipv4, err = regexp.Compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
	if nil != err {
		panic("Internal error.")
	}

	ipv6, err = regexp.Compile("^[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}$")
	if nil != err {
		panic("Internal error.")
	}

	// Is it IPV4?
	if ipv4.MatchString(in_ip) {
		return fmt.Sprintf("%s:%d", in_ip, in_port), nil
	}

	// Is it IPV6?
	if ipv6.MatchString(in_ip) {
		return fmt.Sprintf("[%s]:%d", in_ip, in_port), nil
	}

	return "", errors.New(fmt.Sprintf("Invalid IP address \"%s\"!", in_ip))
}
