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

//! Crypto utils used ethstore and network.

extern crate crypto as rcrypto;
extern crate ethereum_types;
extern crate tiny_keccak;
extern crate ring;

pub mod digest;
pub mod hmac;
pub mod pbkdf2;

use std::fmt;
use tiny_keccak::Keccak;

pub const KEY_LENGTH: usize = 32;
pub const KEY_ITERATIONS: usize = 10240;
pub const KEY_LENGTH_AES: usize = KEY_LENGTH / 2;

/// Default authenticated data to use (in RPC).
pub const DEFAULT_MAC: [u8; 2] = [0, 0];

#[derive(PartialEq, Debug)]
pub enum ScryptError {
	// log(N) < r / 16
	InvalidN,
	// p <= (2^31-1 * 32)/(128 * r)
	InvalidP,
}

impl fmt::Display for ScryptError {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		let s = match *self {
			ScryptError::InvalidN => "Invalid N argument of the scrypt encryption" ,
			ScryptError::InvalidP => "Invalid p argument of the scrypt encryption",
		};

		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Debug)]
pub enum Error {
	Scrypt(ScryptError),
	InvalidMessage,
}

impl From<ScryptError> for Error {
	fn from(err: ScryptError) -> Self {
		Error::Scrypt(err)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		let s = match *self {
			#[cfg(feature = "secp256k1")]
			Error::Scrypt(ref err) => err.to_string(),
			Error::InvalidMessage => "Invalid message".into(),
		};

		write!(f, "{}", s)
	}
}

impl Into<String> for Error {
	fn into(self) -> String {
		format!("{}", self)
	}
}

pub trait Keccak256<T> {
	fn keccak256(&self) -> T where T: Sized;
}

impl<T> Keccak256<[u8; 32]> for T where T: AsRef<[u8]> {
	fn keccak256(&self) -> [u8; 32] {
		let mut keccak = Keccak::new_keccak256();
		let mut result = [0u8; 32];
		keccak.update(self.as_ref());
		keccak.finalize(&mut result);
		result
	}
}

pub fn derive_key_iterations(password: &str, salt: &[u8; 32], c: u32) -> (Vec<u8>, Vec<u8>) {
	let mut derived_key = [0u8; KEY_LENGTH];
	pbkdf2::sha256(c, pbkdf2::Salt(salt), pbkdf2::Secret(password.as_bytes()), &mut derived_key);
	let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
	let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
	(derived_right_bits.to_vec(), derived_left_bits.to_vec())
}

pub fn derive_key_scrypt(password: &str, salt: &[u8; 32], n: u32, p: u32, r: u32) -> Result<(Vec<u8>, Vec<u8>), Error> {
	use rcrypto::scrypt::{scrypt, ScryptParams};
	// sanity checks
	let log_n = (32 - n.leading_zeros() - 1) as u8;
	if log_n as u32 >= r * 16 {
		return Err(Error::Scrypt(ScryptError::InvalidN));
	}

	if p as u64 > ((u32::max_value() as u64 - 1) * 32)/(128 * (r as u64)) {
		return Err(Error::Scrypt(ScryptError::InvalidP));
	}

	let mut derived_key = vec![0u8; KEY_LENGTH];
	let scrypt_params = ScryptParams::new(log_n, r, p);
	scrypt(password.as_bytes(), salt, &scrypt_params, &mut derived_key);
	let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
	let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
	Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
}

pub fn derive_mac(derived_left_bits: &[u8], cipher_text: &[u8]) -> Vec<u8> {
	let mut mac = vec![0u8; KEY_LENGTH_AES + cipher_text.len()];
	mac[0..KEY_LENGTH_AES].copy_from_slice(derived_left_bits);
	mac[KEY_LENGTH_AES..cipher_text.len() + KEY_LENGTH_AES].copy_from_slice(cipher_text);
	mac
}

pub fn is_equal(a: &[u8], b: &[u8]) -> bool {
	ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// AES encryption
pub mod aes {
	use rcrypto::blockmodes::{CtrMode, CbcDecryptor, PkcsPadding};
	use rcrypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
	use rcrypto::symmetriccipher::{Encryptor, Decryptor, SymmetricCipherError};
	use rcrypto::buffer::{RefReadBuffer, RefWriteBuffer, WriteBuffer};

	/// Encrypt a message (CTR mode)
	pub fn encrypt(k: &[u8], iv: &[u8], plain: &[u8], dest: &mut [u8]) {
		let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(k), iv.to_vec());
		encryptor.encrypt(&mut RefReadBuffer::new(plain), &mut RefWriteBuffer::new(dest), true).expect("Invalid length or padding");
	}

	/// Decrypt a message (CTR mode)
	pub fn decrypt(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) {
		let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(k), iv.to_vec());
		encryptor.decrypt(&mut RefReadBuffer::new(encrypted), &mut RefWriteBuffer::new(dest), true).expect("Invalid length or padding");
	}


	/// Decrypt a message using cbc mode
	pub fn decrypt_cbc(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) -> Result<usize, SymmetricCipherError> {
		let mut encryptor = CbcDecryptor::new(AesSafe128Decryptor::new(k), PkcsPadding, iv.to_vec());
		let len = dest.len();
		let mut buffer = RefWriteBuffer::new(dest);
		encryptor.decrypt(&mut RefReadBuffer::new(encrypted), &mut buffer, true)?;
		Ok(len - buffer.remaining())
	}
}

// authenticated encryption with associated data (AES-GCM)
pub mod aes_aead {
	use ring;

	/// Encrypt a message (128bit GCM mode)
	pub fn encrypt<'a>(key: &[u8; 16], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Option<Vec<u8>> {
		let skey = ring::aead::SealingKey::new(&ring::aead::AES_128_GCM, key).ok()?;
		let tag_len = ring::aead::AES_128_GCM.tag_len();
		data.extend(::std::iter::repeat(0).take(tag_len));
		let len = ring::aead::seal_in_place(&skey, nonce, ad, data.as_mut(), tag_len).ok()?;
		data.truncate(len);
		Some(data)
	}

	/// Decrypt a message (128bit GCM mode)
	pub fn decrypt<'a>(key: &[u8; 16], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Option<Vec<u8>> {
		let okey = ring::aead::OpeningKey::new(&ring::aead::AES_128_GCM, key).ok()?;
		let len = ring::aead::open_in_place(&okey, nonce, ad, 0, &mut data).ok()?.len();
		data.truncate(len);
		Some(data)
	}
}

// authenticated encryption with associated data (ChaCha20-Poly1305)
pub mod chacha_poly {
	use ring;

	/// Encrypt a message (ChaCha20-Poly1305)
	pub fn encrypt<'a>(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Option<Vec<u8>> {
		let skey = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305, key).ok()?;
		let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
		data.extend(::std::iter::repeat(0).take(tag_len));
		let len = ring::aead::seal_in_place(&skey, nonce, ad, data.as_mut(), tag_len).ok()?;
		data.truncate(len);
		Some(data)
	}

	/// Decrypt a message (ChaCha20-Poly1305)
	pub fn decrypt<'a>(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], mut data: Vec<u8>) -> Option<Vec<u8>> {
		let okey = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305, key).ok()?;
		let len = ring::aead::open_in_place(&okey, nonce, ad, 0, &mut data).ok()?.len();
		data.truncate(len);
		Some(data)
	}
}

#[cfg(test)]
mod tests {
	use aes_aead;
	use chacha_poly;

	#[test]
	fn aes_aead() {
		let secret = b"1234567890123456";
		let nonce = b"123456789012";
		let message = b"So many books, so little time";

		let data = Vec::from(&message[..]);
		let ciphertext = aes_aead::encrypt(secret, nonce, &[], data).unwrap();
		assert!(ciphertext != message);

		let plain = aes_aead::decrypt(secret, nonce, &[], ciphertext).unwrap();
		assert_eq!(plain, message)
	}

	#[test]
	fn chacha_poly() {
		let secret = b"12345678901234567890123456789012";
		let nonce = b"123456789012";
		let message = b"So many books, so little time";

		let data = Vec::from(&message[..]);
		let ciphertext = chacha_poly::encrypt(secret, nonce, &[], data).unwrap();
		assert!(ciphertext != message);

		let plain = chacha_poly::decrypt(secret, nonce, &[], ciphertext).unwrap();
		assert_eq!(plain, message)
	}
}

