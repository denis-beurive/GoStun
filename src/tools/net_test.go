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

import "testing"
import "fmt"
import "strings"

// InetSplit()
func Test_InetSplit(in_test *testing.T) {
	var ip string
	var port int
	var err error

	// ----------------------------------------------------------------------
	// Testing IPV4
	// ----------------------------------------------------------------------

	// Test OK
	ip, port, err = InetSplit("192.168.0.1:80")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}
	if ip != "192.168.0.1" {
		in_test.Errorf("Extracted IP: %s, given %s", ip, in_test)
	}
	if port != 80 {
		in_test.Errorf("Extracted port number: %d, given %s", port, in_test)
	}

	// Test KO
	ip, port, err = InetSplit("192.168.0.1.15.16:80")
	if nil == err {
		in_test.Errorf("The test should fail.")
	}

	// ----------------------------------------------------------------------
	// Testing IPV6
	// ----------------------------------------------------------------------

	// Test OK
	ip, port, err = InetSplit("[0011:2233:4455:6677:8899:AABB:CCDD:EEFF]:125")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}
	if ip != "0011:2233:4455:6677:8899:AABB:CCDD:EEFF" {
		in_test.Errorf("Extracted IP: %s, given %s", ip, in_test)
	}
	if port != 125 {
		in_test.Errorf("Extracted port number: %d, given %s", port, in_test)
	}

	// Test OK
	ip, port, err = InetSplit("[0011:22:4455:6677:8899:A:CCDD:E]:125")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}
	if ip != "0011:22:4455:6677:8899:A:CCDD:E" {
		in_test.Errorf("Extracted IP: %s, given %s", ip, in_test)
	}
	if port != 125 {
		in_test.Errorf("Extracted port number: %d, given %s", port, in_test)
	}

	// Test OK
	ip, port, err = InetSplit("[0011:22:4455:6677:8899:A:CCDD:abcd]:125")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}
	if ip != "0011:22:4455:6677:8899:A:CCDD:abcd" {
		in_test.Errorf("Extracted IP: %s, given %s", ip, in_test)
	}
	if port != 125 {
		in_test.Errorf("Extracted port number: %d, given %s", port, in_test)
	}

	// Test KO
	ip, port, err = InetSplit("[0011:22:4455:6677:8899:A:CCDD:E:A]:125")
	if nil == err {
		in_test.Errorf("The test should fail.")
	}
}

// IpToBytes()
func Test_IpToBytes(in_test *testing.T) {
	// Test OK
	bytes, err := IpToBytes("192.168.0.1")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}
	if 192 != bytes[0] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 192", bytes[0])
	}
	if 168 != bytes[1] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 168", bytes[1])
	}
	if 0 != bytes[2] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 0  ", bytes[2])
	}
	if 1 != bytes[3] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 1  ", bytes[3])
	}

	// Test OK
	bytes, err = IpToBytes("0011:2233:4455:6677:8899:AABB:CCDD:EEFF")
	if nil != err {
		in_test.Errorf("Error: %s", err)
	}

	if 0x00 != bytes[0] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 00", bytes[0])
	}
	if 0x11 != bytes[1] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 11", bytes[1])
	}
	if 0x22 != bytes[2] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 22", bytes[2])
	}
	if 0x33 != bytes[3] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 33", bytes[3])
	}
	if 0x44 != bytes[4] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 44", bytes[4])
	}
	if 0x55 != bytes[5] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 55", bytes[5])
	}
	if 0x66 != bytes[6] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 66", bytes[6])
	}
	if 0x77 != bytes[7] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 77", bytes[7])
	}
	if 0x88 != bytes[8] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 88", bytes[8])
	}
	if 0x99 != bytes[9] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: 99", bytes[9])
	}
	if 0xAA != bytes[10] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: AA", bytes[10])
	}
	if 0xBB != bytes[11] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: BB", bytes[11])
	}
	if 0xCC != bytes[12] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: CC", bytes[12])
	}
	if 0xDD != bytes[13] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: DD", bytes[13])
	}
	if 0xEE != bytes[14] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: EE", bytes[14])
	}
	if 0xFF != bytes[15] {
		in_test.Errorf("Byte is not valid. Extracted: %d, given: FF", bytes[15])
	}

	// Test KO
	bytes, err = IpToBytes("800.168.0.1")
	if nil == err {
		in_test.Errorf("Error: the test should have failed!")
	}

	// Test KO
	bytes, err = IpToBytes("800.168.0.1.12")
	if nil == err {
		in_test.Errorf("Error: the test should have failed!")
	}

	// Test KO
	bytes, err = IpToBytes("FFFFA.2233.4455.6677.8899.AABB.CCDD.EEFF")
	if nil == err {
		in_test.Errorf("Error: the test should have failed!")
	}

}

// BytesToIp
func Test_BytesToIp(in_test *testing.T) {
	var err error
	var ip string
	ipv4 := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	ipv6 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	ip, err = BytesToIp(ipv4)
	if nil != err {
		in_test.Errorf(fmt.Sprintf("%s", err))
	}
	fmt.Println(fmt.Sprintf("IP = %s", ip))
	if "170.187.204.221" != ip {
		in_test.Errorf(fmt.Sprintf("Invalid IPV4: given 170.187.204.221, got %s", ip))
	}

	ip, err = BytesToIp(ipv6)
	if nil != err {
		in_test.Errorf(fmt.Sprintf("%s", err))
	}
	fmt.Println(fmt.Sprintf("IP = %s", ip))
	if "0011:2233:4455:6677:8899:AABB:CCDD:EEFF" != strings.ToUpper(ip) {
		in_test.Errorf(fmt.Sprintf("Invalid IPV4: given 0011.2233.4455.6677.8899.AABB.CCDD.EEFF, got %s", ip))
	}

	ipv4 = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	ip, err = BytesToIp(ipv4)
	if nil == err {
		in_test.Errorf(fmt.Sprintf("Test should not succeed."))
	}

	ipv4 = []byte{0xAA, 0xBB, 0xCC}
	ip, err = BytesToIp(ipv4)
	if nil == err {
		in_test.Errorf(fmt.Sprintf("Test should not succeed."))
	}

	ipv6 = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	ip, err = BytesToIp(ipv6)
	if nil == err {
		in_test.Errorf(fmt.Sprintf("Test should not succeed."))
	}
}

func Test_MakeTransportAddress(in_test *testing.T) {
	var err error
	var transport string

	transport, err = MakeTransportAddress("1.2.3.4", 123)
	if nil != err {
		in_test.Errorf(fmt.Sprintf("%s", err))
	}
	if "1.2.3.4:123" != transport {
		in_test.Errorf(fmt.Sprintf("Invalid transport address %s", transport))
	}

	transport, err = MakeTransportAddress("1:2:3:4:5:6:7:8", 123)
	if nil != err {
		in_test.Errorf(fmt.Sprintf("%s", err))
	}
	if "[1:2:3:4:5:6:7:8]:123" != transport {
		in_test.Errorf(fmt.Sprintf("Invalid transport address %s", transport))
	}
}
