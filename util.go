package main

import (
	"bytes"
	"encoding/hex"
)

// Helper function to make a spaced hex string.
func makeSpacedHex(data []byte) string {
	s := hex.EncodeToString(data)

	var buffer bytes.Buffer
	var strEnd = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%2 == 1 && i != strEnd {
			buffer.WriteRune(' ')
		}
	}
	return buffer.String()
}
