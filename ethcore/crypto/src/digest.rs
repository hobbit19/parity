// Copyright 2018 Parity Technologies (UK) Ltd.
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

use ring::digest::{self, Context, SHA256, SHA512};
use std::marker::PhantomData;
use std::ops::Deref;

pub struct Digest<T>(digest::Digest, PhantomData<T>);

impl<T> Deref for Digest<T> {
	type Target = [u8];
	fn deref(&self) -> &Self::Target {
		self.0.as_ref()
	}
}

/// Single-step sha256 digest computation.
pub fn sha256(data: &[u8]) -> Digest<Sha256> {
	Digest(digest::digest(&SHA256, data), PhantomData)
}

/// Single-step sha512 digest computation.
pub fn sha512(data: &[u8]) -> Digest<Sha512> {
	Digest(digest::digest(&SHA512, data), PhantomData)
}

pub enum Sha256 {}
pub enum Sha512 {}

pub struct Hasher<T>(Context, PhantomData<T>);

impl Hasher<Sha256> {
	pub fn sha256() -> Hasher<Sha256> {
		Hasher(Context::new(&SHA256), PhantomData)
	}
}

impl Hasher<Sha512> {
	pub fn sha512() -> Hasher<Sha512> {
		Hasher(Context::new(&SHA512), PhantomData)
	}
}

impl<T> Hasher<T> {
	pub fn update(&mut self, data: &[u8]) {
		self.0.update(data)
	}

	pub fn finish(self) -> Digest<T> {
		Digest(self.0.finish(), PhantomData)
	}
}
