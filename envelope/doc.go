// Package envelope implements keyforge's self-describing ciphertext format:
// its binary and text forms, the authenticated header, and sealing and
// opening of the payload.
//
// The format is frozen once data exists. Any change needs a new format
// version, new known-answer vectors in testdata, and a fuzz run. Unknown
// versions, modes, algorithms and flags fail with typed errors; the parser
// never guesses.
//
// # Layout
//
// Version 1, big-endian:
//
//	magic "KF" | format u8 | mode u8 | algorithm u8 | flags u8
//	purpose   : len u8 + bytes
//	reference : dek_id 16 bytes                          (reference mode)
//	inline    : kek_id 16 bytes, kek_version u32,
//	            wrapped_len u16, wrapped                 (inline mode)
//	nonce     : 12 bytes
//	ciphertext || tag
//
// The additional authenticated data is the header bytes up to the nonce,
// followed by the caller's context, so changing the purpose, key, mode,
// algorithm or context makes decryption fail.
//
// The text form is "kf1." followed by unpadded base64url of the binary form.
package envelope
