// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use crate::Group;
use digest::block_api::BlockSizeUser;
use digest::typenum::{IsLess, IsLessOrEqual, U256};
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use hash2curve::{ExpandMsg, GroupDigest, MapToCurve, OprfParameters};
use hybrid_array::ArraySize;
use hybrid_array::typenum::{IsGreaterOrEqual, Prod, True, U2};

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
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
    type Hash: BlockSizeUser + Default + FixedOutput + HashMarker;
}

/// The hash function associated with a curve's OPRF `expand_message` implementation.
type OprfHash<T> =
    <<T as GroupDigest>::ExpandMsg as ExpandMsg<<T as MapToCurve>::SecurityLevel>>::Hash;

impl<T: OprfParameters> CipherSuite for T
where
    T: Group,
    OprfHash<T>: BlockSizeUser + Default + FixedOutput + HashMarker,
    <OprfHash<T> as OutputSizeUser>::OutputSize: ArraySize
        + IsLess<U256>
        + IsLessOrEqual<<OprfHash<T> as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<T as Group>::SecurityLevel, U2>, Output = True>,
{
    const ID: &'static [u8] = T::ID;
    type Group = T;
    type Hash = OprfHash<T>;
}
