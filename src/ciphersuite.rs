// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use crate::Group;
use core::ops::Mul;
use digest::block_api::BlockSizeUser;
use digest::typenum::{IsLess, IsLessOrEqual, U256};
use digest::{Digest, FixedOutput, HashMarker, OutputSizeUser};
use hash2curve::{ExpandMsg, GroupDigest, OprfParameters};
use hybrid_array::ArraySize;
use hybrid_array::typenum::{IsGreaterOrEqual, Prod, True, U2};

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
    <Self::Group as Group>::SecurityLevel: Mul<U2>,
    <Self::Hash as OutputSizeUser>::OutputSize: ArraySize
        + IsLess<U256>
        + IsLessOrEqual<<Self::Hash as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<Self::Group as Group>::SecurityLevel, U2>, Output = True>,
{
    /// The ciphersuite identifier as dictated by
    /// <https://www.rfc-editor.org/rfc/rfc9497>
    const ID: &'static [u8];

    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See [`Group`].
    type Group: Group;

    /// The main hash function to use (for HKDF computations and hashing
    /// transcripts).
    type Hash: Digest + BlockSizeUser + Default + FixedOutput + HashMarker;
}

/// Trait associating a hash to an elliptic curve for OPRF usage.
pub trait OprfCipherSuite: OprfParameters + Group {
    type Hash: Digest + BlockSizeUser + Default + FixedOutput + HashMarker + OutputSizeUser;
}

impl<T> OprfCipherSuite for T
where
    T: OprfParameters + Group,
    <T as GroupDigest>::ExpandMsg: ExpandMsg<<T as Group>::SecurityLevel>,
    <<T as GroupDigest>::ExpandMsg as ExpandMsg<<T as Group>::SecurityLevel>>::Hash:
        Digest + BlockSizeUser + Default + FixedOutput + HashMarker + OutputSizeUser,
{
    type Hash = <<T as GroupDigest>::ExpandMsg as ExpandMsg<<T as Group>::SecurityLevel>>::Hash;
}

impl<T: OprfCipherSuite> CipherSuite for T
where
    T: Group,
    <T as Group>::SecurityLevel: Mul<U2>,
    <<T as OprfCipherSuite>::Hash as OutputSizeUser>::OutputSize: ArraySize
        + IsLess<U256>
        + IsLessOrEqual<<<T as OprfCipherSuite>::Hash as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<T as Group>::SecurityLevel, U2>, Output = True>,
{
    const ID: &'static [u8] = T::ID;
    type Group = T;
    type Hash = <T as OprfCipherSuite>::Hash;
}
