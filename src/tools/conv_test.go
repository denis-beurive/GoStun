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

func Test_Uint16toBytesLSF(in_test *testing.T) {
	b := Uint16toBytesLSF(0xFFAA)
	if b[1] != 0xFF {
		in_test.Errorf("First byte is not valid. Got %d, expected %d", b[1], 0xFF)
	}
	if b[0] != 0xAA {
		in_test.Errorf("First byte is not valid. Got %d, expected %d", b[0], 0xAA)
	}
}

func Test_Uint16toBytesMSF(in_test *testing.T) {
	b := Uint16toBytesMSF(0xFFAA)
	if b[1] != 0xAA {
		in_test.Errorf("First byte is not valid. Got %d, expected %d", b[1], 0xAA)
	}
	if b[0] != 0xFF {
		in_test.Errorf("First byte is not valid. Got %d, expected %d", b[0], 0xFF)
	}
}
