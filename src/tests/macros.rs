// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.

macro_rules! test_all_curves {
    ($($test_fn:ident),+ $(,)?) => {
        #[test]
        fn test_functionality() -> $crate::Result<()> {
            #[cfg(feature = "ristretto255")]
            {
                $( $test_fn::<$crate::Ristretto255>(); )+
            }
            $( $test_fn::<::p256::NistP256>(); )+
            $( $test_fn::<::p384::NistP384>(); )+
            $( $test_fn::<::p521::NistP521>(); )+
            Ok(())
        }
    };
}

pub(crate) use test_all_curves;
