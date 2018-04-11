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


use ring::digest::{self, Context, SHA256};

pub struct Digest(digest::Digest);

impl AsRef<[u8]> for Digest {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

/// Single-step sha256 digest computation.
pub fn sha256(data: &[u8]) -> Digest {
	Digest(digest::digest(&SHA256, data))
}

pub struct Sha256(Context);

impl Sha256 {
	pub fn new() -> Sha256 {
		Sha256(Context::new(&SHA256))
	}

	pub fn update(&mut self, data: &[u8]) {
		self.0.update(data)
	}

	pub fn finish(self) -> Digest {
		Digest(self.0.finish())
	}
}
