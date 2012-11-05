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

import "encoding/binary"
import "bytes"

// This function converts a two bytes long unsigned integer into a slice of two bytes.
// The first element of the returned slice represents the least significant byte of the given integer.
// Example: b := Uint16toBytesLSF(0xFFAA)
//          Then b[0] = 0xAA and b[1] = 0xFF. That is: b := []byte{0xAA, 0xFF}
// 
// INPUT
// - in_uint16: the two bytes long unsigned integer.
//
// OUTPUT
// - The slice.
func Uint16toBytesLSF(in_uint16 uint16) ([]byte) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, in_uint16)
	if (nil != err) { panic("Internal error") }
	return buf.Bytes()
}

// This function converts a two bytes long unsigned integer into a slice of two bytes.
// The first element of the returned slice represents the most significant byte of the given integer.
// Example: b := Uint16toBytesMSF(0xFFAA)
//          Then b[0] = 0xFF and b[1] = 0xAA. That is: b := []byte{0xFF, 0xAA}
// 
// INPUT
// - in_uint16: the two bytes long unsigned integer.
//
// OUTPUT
// - The slice.
func Uint16toBytesMSF(in_uint16 uint16) ([]byte) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, in_uint16)
	if (nil != err) { panic("Internal error") }
	return buf.Bytes()
}
