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

// RFC 3489
const STUN_RFC_3489 = 0

// RFC 5389
const STUN_RFC_5389 = 0

// The chosen RFC used for compliance.
var rfc int = STUN_RFC_3489

// Set RFC to 3489.
func  SetRfc3489() { rfc = STUN_RFC_3489 }

// Set RFC to 5389
func  SetRfc5389() { rfc = STUN_RFC_5389 }

