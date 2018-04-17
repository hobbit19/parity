// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use error::SymmError;
use ring;

/// Encrypt a message (ChaCha20-Poly1305).
///
/// NOTE: The pair (key, nonce) must never be reused.
///
/// The associated data `ad` can be empty.
pub fn encrypt<'a>(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, SymmError> {
	let skey = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305, key)?;
	let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
	data.extend(::std::iter::repeat(0).take(tag_len));
	let len = ring::aead::seal_in_place(&skey, nonce, ad, data.as_mut(), tag_len)?;
	data.truncate(len);
	Ok(data)
}

/// Decrypt a message (ChaCha20-Poly1305).
pub fn decrypt<'a>(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, SymmError> {
	let okey = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305, key)?;
	let len = ring::aead::open_in_place(&okey, nonce, ad, 0, &mut data)?.len();
	data.truncate(len);
	Ok(data)
}

#[cfg(test)]
mod tests {

	#[test]
	fn chacha_poly() {
		let secret = b"12345678901234567890123456789012";
		let nonce = b"123456789012";
		let message = b"So many books, so little time";

		let data = Vec::from(&message[..]);
		let ciphertext = super::encrypt(secret, nonce, &[], data).unwrap();
		assert!(ciphertext != message);

		let plain = super::decrypt(secret, nonce, &[], ciphertext).unwrap();
		assert_eq!(plain, message)
	}
}

