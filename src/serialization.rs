// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

//! Handles the serialization of each of the components used in the VOPRF
//! protocol

use hybrid_array::Array;
use hybrid_array::typenum::{Sum, Unsigned};

use crate::{
    BlindedElement, CipherSuite, Error, EvaluationElement, Group, OprfClient, OprfServer,
    PoprfClient, PoprfServer, Proof, Result, VoprfClient, VoprfServer,
};

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

/// Length of [`OprfClient`] in bytes for serialization.
pub type OprfClientLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> OprfClient<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, OprfClientLen<CS>> {
        CS::Group::serialize_scalar(self.blind)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let blind = deserialize_scalar::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self { blind })
    }
}

/// Length of [`VoprfClient`] in bytes for serialization.
pub type VoprfClientLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VoprfClient<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, VoprfClientLen<CS>> {
        <CS::Group as Group>::serialize_scalar(self.blind)
            .concat(<CS::Group as Group>::serialize_elem(self.blinded_element))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let blind = deserialize_scalar::<CS::Group>(&mut input)?;
        let blinded_element = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self {
            blind,
            blinded_element,
        })
    }
}

/// Length of [`PoprfClient`] in bytes for serialization.
pub type PoprfClientLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> PoprfClient<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, PoprfClientLen<CS>> {
        <CS::Group as Group>::serialize_scalar(self.blind)
            .concat(<CS::Group as Group>::serialize_elem(self.blinded_element))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let blind = deserialize_scalar::<CS::Group>(&mut input)?;
        let blinded_element = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self {
            blind,
            blinded_element,
        })
    }
}

/// Length of [`OprfServer`] in bytes for serialization.
pub type OprfServerLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> OprfServer<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, OprfServerLen<CS>> {
        CS::Group::serialize_scalar(self.sk)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let sk = deserialize_scalar::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self { sk })
    }
}

/// Length of [`VoprfServer`] in bytes for serialization.
pub type VoprfServerLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VoprfServer<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, VoprfServerLen<CS>> {
        CS::Group::serialize_scalar(self.sk).concat(CS::Group::serialize_elem(self.pk))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let sk = deserialize_scalar::<CS::Group>(&mut input)?;
        let pk = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self { sk, pk })
    }
}

/// Length of [`PoprfServer`] in bytes for serialization.
pub type PoprfServerLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> PoprfServer<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, PoprfServerLen<CS>> {
        CS::Group::serialize_scalar(self.sk).concat(CS::Group::serialize_elem(self.pk))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let sk = deserialize_scalar::<CS::Group>(&mut input)?;
        let pk = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self { sk, pk })
    }
}

/// Length of [`Proof`] in bytes for serialization.
pub type ProofLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
>;

impl<CS: CipherSuite> Proof<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, ProofLen<CS>> {
        CS::Group::serialize_scalar(self.c_scalar)
            .concat(CS::Group::serialize_scalar(self.s_scalar))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let c_scalar = deserialize_scalar::<CS::Group>(&mut input)?;
        let s_scalar = deserialize_scalar::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Proof { c_scalar, s_scalar })
    }
}

/// Length of [`BlindedElement`] in bytes for serialization.
pub type BlindedElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> BlindedElement<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, BlindedElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let value = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self(value))
    }
}

/// Length of [`EvaluationElement`] in bytes for serialization.
pub type EvaluationElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> EvaluationElement<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Array<u8, EvaluationElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(mut input: &[u8]) -> Result<Self> {
        let value = deserialize_elem::<CS::Group>(&mut input)?;

        if !input.is_empty() {
            return Err(Error::Deserialization);
        }

        Ok(Self(value))
    }
}

fn deserialize_elem<G: Group>(input: &mut &[u8]) -> Result<G::Elem> {
    let input = input
        .take_ext(G::ElemLen::USIZE)
        .ok_or(Error::Deserialization)?;
    G::deserialize_elem(input)
}

fn deserialize_scalar<G: Group>(input: &mut &[u8]) -> Result<G::Scalar> {
    let input = input
        .take_ext(G::ScalarLen::USIZE)
        .ok_or(Error::Deserialization)?;
    G::deserialize_scalar(input)
}

trait SliceExt {
    fn take_ext<'a>(self: &mut &'a Self, take: usize) -> Option<&'a Self>;
}

impl<T> SliceExt for [T] {
    fn take_ext<'a>(self: &mut &'a Self, take: usize) -> Option<&'a Self> {
        if take > self.len() {
            return None;
        }

        let (front, back) = self.split_at(take);
        *self = back;
        Some(front)
    }
}

#[cfg(feature = "serde")]
pub(crate) mod serde {
    use core::marker::PhantomData;

    use hybrid_array::Array;
    use serde::de::{Deserializer, Error};
    use serde::ser::Serializer;
    use serde::{Deserialize, Serialize};

    use crate::Group;

    pub(crate) struct Element<G: Group>(PhantomData<G>);

    impl<'de, G: Group> Element<G> {
        pub(crate) fn deserialize<D>(deserializer: D) -> Result<G::Elem, D::Error>
        where
            D: Deserializer<'de>,
        {
            Array::<_, G::ElemLen>::deserialize(deserializer)
                .and_then(|bytes| G::deserialize_elem(&bytes).map_err(D::Error::custom))
        }

        pub(crate) fn serialize<S>(self_: &G::Elem, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            G::serialize_elem(*self_).serialize(serializer)
        }
    }

    pub(crate) struct Scalar<G: Group>(PhantomData<G>);

    impl<'de, G: Group> Scalar<G> {
        pub(crate) fn deserialize<D>(deserializer: D) -> Result<G::Scalar, D::Error>
        where
            D: Deserializer<'de>,
        {
            Array::<_, G::ScalarLen>::deserialize(deserializer)
                .and_then(|bytes| G::deserialize_scalar(&bytes).map_err(D::Error::custom))
        }

        pub(crate) fn serialize<S>(self_: &G::Scalar, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            G::serialize_scalar(*self_).serialize(serializer)
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::{
        BlindedElement, EvaluationElement, OprfClient, OprfServer, PoprfClient, PoprfServer, Proof,
        VoprfClient, VoprfServer,
    };

    // Fuzz: no panics on arbitrary input
    macro_rules! test_deserialize {
        ($item:ident, $bytes:ident) => {
            #[cfg(feature = "ristretto255")]
            {
                let _ = $item::<crate::Ristretto255>::deserialize(&$bytes[..]);
            }

            let _ = $item::<::p256::NistP256>::deserialize(&$bytes[..]);
            let _ = $item::<::p384::NistP384>::deserialize(&$bytes[..]);
            let _ = $item::<::p521::NistP521>::deserialize(&$bytes[..]);
        };
    }

    // Roundtrip: serialize to deserialize == original
    macro_rules! test_roundtrip {
        ($item:ident, $cs:ty, $constructor:expr) => {{
            let original = $constructor;
            let bytes = original.serialize();
            let recovered = $item::<$cs>::deserialize(&bytes).expect("roundtrip deserialize");
            assert_eq!(original.serialize(), recovered.serialize());
        }};
    }

    // Trailing bytes: valid serialization + extra byte must fail
    macro_rules! test_trailing {
        ($item:ident, $cs:ty, $constructor:expr) => {{
            let original = $constructor;
            let bytes = original.serialize();
            let mut extended = bytes.to_vec();
            extended.push(0x00);
            assert!($item::<$cs>::deserialize(&extended).is_err());
        }};
    }

    // Truncated: valid serialization minus one byte must fail
    macro_rules! test_truncated {
        ($item:ident, $cs:ty, $constructor:expr) => {{
            let original = $constructor;
            let bytes = original.serialize();
            let truncated = &bytes[..bytes.len() - 1];
            assert!($item::<$cs>::deserialize(truncated).is_err());
        }};
    }

    proptest! {
        #[test]
        fn test_nocrash_oprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(OprfClient, bytes);
        }

        #[test]
        fn test_nocrash_voprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VoprfClient, bytes);
        }

        #[test]
        fn test_nocrash_poprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(PoprfClient, bytes);
        }

        #[test]
        fn test_nocrash_oprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(OprfServer, bytes);
        }

        #[test]
        fn test_nocrash_voprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VoprfServer, bytes);
        }

        #[test]
        fn test_nocrash_poprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(PoprfServer, bytes);
        }


        #[test]
        fn test_nocrash_blinded_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(BlindedElement, bytes);
        }

        #[test]
        fn test_nocrash_evaluation_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(EvaluationElement, bytes);
        }

        #[test]
        fn test_nocrash_proof(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(Proof, bytes);
        }
    }

    macro_rules! structured_tests {
        ($cs:ty, $mod:ident) => {
            mod $mod {
                use super::*;

                use rand::rngs::SysRng;

                #[test]
                fn roundtrip_oprf_client() {
                    let client = OprfClient::<$cs>::blind(b"input", &mut SysRng)
                        .expect("blind")
                        .state;
                    test_roundtrip!(OprfClient, $cs, client);
                }

                #[test]
                fn roundtrip_oprf_server() {
                    let server = OprfServer::<$cs>::new(&mut SysRng).expect("new");
                    test_roundtrip!(OprfServer, $cs, server);
                }

                #[test]
                fn roundtrip_voprf_client() {
                    let client = VoprfClient::<$cs>::blind(b"input", &mut SysRng)
                        .expect("blind")
                        .state;
                    test_roundtrip!(VoprfClient, $cs, client);
                }

                #[test]
                fn roundtrip_voprf_server() {
                    let server = VoprfServer::<$cs>::new(&mut SysRng).expect("new");
                    test_roundtrip!(VoprfServer, $cs, server);
                }

                #[test]
                fn roundtrip_poprf_client() {
                    let client = PoprfClient::<$cs>::blind(b"input", &mut SysRng)
                        .expect("blind")
                        .state;
                    test_roundtrip!(PoprfClient, $cs, client);
                }

                #[test]
                fn roundtrip_poprf_server() {
                    let server = PoprfServer::<$cs>::new(&mut SysRng).expect("new");
                    test_roundtrip!(PoprfServer, $cs, server);
                }

                #[test]
                fn trailing_oprf_client() {
                    let client = OprfClient::<$cs>::blind(b"input", &mut SysRng)
                        .expect("blind")
                        .state;
                    test_trailing!(OprfClient, $cs, client);
                }

                #[test]
                fn trailing_oprf_server() {
                    let server = OprfServer::<$cs>::new(&mut SysRng).expect("new");
                    test_trailing!(OprfServer, $cs, server);
                }

                #[test]
                fn truncated_oprf_client() {
                    let client = OprfClient::<$cs>::blind(b"input", &mut SysRng)
                        .expect("blind")
                        .state;
                    test_truncated!(OprfClient, $cs, client);
                }

                #[test]
                fn truncated_oprf_server() {
                    let server = OprfServer::<$cs>::new(&mut SysRng).expect("new");
                    test_truncated!(OprfServer, $cs, server);
                }

                #[test]
                fn empty_input_fails() {
                    assert!(OprfClient::<$cs>::deserialize(&[]).is_err());
                    assert!(OprfServer::<$cs>::deserialize(&[]).is_err());
                    assert!(VoprfClient::<$cs>::deserialize(&[]).is_err());
                    assert!(VoprfServer::<$cs>::deserialize(&[]).is_err());
                    assert!(PoprfClient::<$cs>::deserialize(&[]).is_err());
                    assert!(PoprfServer::<$cs>::deserialize(&[]).is_err());
                    assert!(BlindedElement::<$cs>::deserialize(&[]).is_err());
                    assert!(EvaluationElement::<$cs>::deserialize(&[]).is_err());
                    assert!(Proof::<$cs>::deserialize(&[]).is_err());
                }
            }
        };
    }

    #[cfg(feature = "ristretto255")]
    structured_tests!(crate::Ristretto255, ristretto255);
    structured_tests!(::p256::NistP256, p256);
    structured_tests!(::p384::NistP384, p384);
    structured_tests!(::p521::NistP521, p521);
}
