// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.

use core::iter;

use digest::Output;

use crate::common::{Dst, Mode, STR_HASH_TO_GROUP, finalize_after_unblind};
use crate::{CipherSuite, Group};

pub(crate) fn prf<CS: CipherSuite>(
    input: &[u8],
    key: <CS::Group as Group>::Scalar,
    mode: Mode,
) -> Output<CS::Hash> {
    let dst = Dst::new::<CS, _>(STR_HASH_TO_GROUP, mode);
    let point = CS::Group::hash_to_curve::<CS::Hash>(&[input], &dst.as_dst()).unwrap();

    let res = point * &key;

    finalize_after_unblind::<CS, _, _>(iter::once((input, res)))
        .next()
        .unwrap()
        .unwrap()
}
