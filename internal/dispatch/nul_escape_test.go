package dispatch

import "testing"

// hasNULEscape must distinguish a real NUL escape (jsonb refuses it) from the
// six printable characters backslash-u-0-0-0-0 inside a string, which JSON
// encodes with a doubled backslash: the first version matched raw bytes, and a
// banner carrying that printable text voided a whole submission as malformed.
func TestHasNULEscapeReadsEscapesNotBytes(t *testing.T) {
	bs := `\`
	cases := map[string]bool{
		`{"v":"a` + bs + `u0000b"}`:           true,  // one backslash: a real escape
		`{"v":"a` + bs + bs + `u0000b"}`:      false, // escaped backslash, then the text u0000
		`{"v":"a` + bs + bs + bs + `u0000b"}`: true,  // escaped backslash, then a real escape
		`{"v":"plain"}`:                       false,
		`{"v":"` + bs + `u00000"}`:            true,
		`{"v":"u0000 no escape"}`:             false,
		`{"v":"` + bs + bs + `"}`:             false,
	}
	for in, want := range cases {
		if got := hasNULEscape([]byte(in)); got != want {
			t.Errorf("hasNULEscape(%s) = %v, want %v", in, got, want)
		}
	}
}
