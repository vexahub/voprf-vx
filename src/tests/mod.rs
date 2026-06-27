// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

mod cfrg_vectors;
mod mock_rng;
mod parser;
mod test_cfrg_vectors;

impl crate::CipherSuite for p256::NistP256 {
    const ID: &'static [u8] = <p256::NistP256 as hash2curve::OprfParameters>::ID;
    type Group = p256::NistP256;
    type Hash = sha2::Sha256;
}

impl crate::CipherSuite for p384::NistP384 {
    const ID: &'static [u8] = <p384::NistP384 as hash2curve::OprfParameters>::ID;
    type Group = p384::NistP384;
    type Hash = sha2::Sha384;
}

impl crate::CipherSuite for p521::NistP521 {
    const ID: &'static [u8] = <p521::NistP521 as hash2curve::OprfParameters>::ID;
    type Group = p521::NistP521;
    type Hash = sha2::Sha512;
}
