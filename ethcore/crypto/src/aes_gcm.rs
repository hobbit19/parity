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

/// Encrypt a message (128bit GCM mode).
///
/// NOTE: The pair (key, nonce) must never be reused. Using random nonces limits
/// the number of messages encrypted with the same key to 2^32 (cf. [[1]])
///
/// The associated data `ad` can be empty.
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
pub fn encrypt<'a>(key: &[u8; 16], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, SymmError> {
	let skey = ring::aead::SealingKey::new(&ring::aead::AES_128_GCM, key)?;
	let tag_len = ring::aead::AES_128_GCM.tag_len();
	data.extend(::std::iter::repeat(0).take(tag_len));
	let len = ring::aead::seal_in_place(&skey, nonce, ad, data.as_mut(), tag_len)?;
	data.truncate(len);
	Ok(data)
}

/// Decrypt a message (128bit GCM mode).
pub fn decrypt<'a>(key: &[u8; 16], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, SymmError> {
	let okey = ring::aead::OpeningKey::new(&ring::aead::AES_128_GCM, key)?;
	let len = ring::aead::open_in_place(&okey, nonce, ad, 0, &mut data)?.len();
	data.truncate(len);
	Ok(data)
}

#[cfg(test)]
mod tests {

	#[test]
	fn aes_gcm() {
		let secret = b"1234567890123456";
		let nonce = b"123456789012";
		let message = b"So many books, so little time";

		let data = Vec::from(&message[..]);
		let ciphertext = super::encrypt(secret, nonce, &[], data).unwrap();
		assert!(ciphertext != message);

		let plain = super::decrypt(secret, nonce, &[], ciphertext).unwrap();
		assert_eq!(plain, message)
	}
}
