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

import "fmt"

// This function is used to add message to a messages' spool.
//
// INPUT
// - out_text: messages' spool.
//   If this parameter is nil, then the message will be printed in through the standard output.
//   Otherwize, the message will be appended to the spool.
// - in_message: message to add.
func AddText(out_text *[]string, in_message string) {
	if (nil == out_text) {
		fmt.Println(in_message)
	} else {
		*out_text = append(*out_text, in_message)
	}
}



