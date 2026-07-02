# Changelog

## 1.0.0-rc.1 (July 3, 2026)

* Reject trailing bytes in all `deserialize` methods
* Reject identity element in `deterministic_blind_unchecked` to prevent blinding bypass
* Added roundtrip, trailing bytes, truncated, and empty input tests for serialization

## 1.0.0-rc.0 (July 2, 2026)

* Added missing license in Cargo manifest
* Implement `zeroize` feature for `digest`, `hybrid-array` and `sha2`
* Replaced license appendix in files while keeping original copyright

## 1.0.0-pre.1 (July 2, 2026)

* Simplified ciphersuite trait
* Moved multiplication operator to SecurityLevel type in Group trait

## 1.0.0-pre.0 (June 29, 2026)

Forked from [facebook/voprf](https://github.com/facebook/voprf/) at `0.6.0-pre.1`.

* MSRV bumped to 1.87
* Migrated from `elliptic-curve 0.13` to `0.14`
* Replaced `generic-array` with `hybrid-array 0.4`
* Updated `digest` to 0.11, `rand_core` to 0.10, `rand` to 0.10, `sha2` to 0.11
* Updated `p256`, `p384`, `p521` to `0.14`
* Replaced `elliptic-curve/hash2curve` feature with standalone `hash2curve 0.14` crate
* Removed `VoprfParameters` dependency to be replaced with `OprfParameters` + `GroupDigest`
* Added `SecurityLevel` associated type to `Group` trait for generic hash bounds
* Added `OkmLen` associated type to `Group` trait (`MapToCurve::Length`)
* Updated `hash_to_scalar` to use `MapToCurve::Length` as OKM length per RFC 9380
* Updated `random_scalar` for deterministic byte consumption with `rand_core 0.10`
* Auto-impl `CipherSuite` for any `OprfParameters + Group` type via `OprfHash<T>`

## 0.6.0-pre.1 (April 6, 2026)

* MSRV bumped to 1.85
* Updated rand_core dependency to 0.9
* Updated rand dependency to 0.9
* Updated subtle dependency to 2.6
* Fixed docs issue

## 0.6.0-pre.0 (November 8, 2025)

* MSRV bumped to 1.83
* Updated Ristretto255 random scalar generation
* Updated generic-array to v1

## 0.5.0 (March 6, 2024)

* Just a version bump from v0.5.0-pre.7

## 0.5.0-pre.7 (January 11, 2024)

* Updated to be in sync with RFC 9497

## 0.5.0-pre.6 (July 24, 2023)

* Updated curve25519-dalek dependency to 4

## 0.5.0-pre.5 (June 27, 2023)

* Updated curve25519-dalek dependency to 4.0.0-rc.3

## 0.5.0-pre.4 (May 20, 2023)

* Updated curve25519-dalek dependency to 4.0.0-rc.2

## 0.5.0-pre.3 (March 4, 2023)

* Updated to be in sync with draft-irtf-cfrg-voprf-19
* Increased MSRV to 1.65
* Updated p256 dependency to v0.13
* Added p384 tests

## 0.5.0-pre.2 (February 3, 2023)

* Increased MSRV to 1.60
* Updated p256 dependency to v0.12
* Updated curve25519-dalek dependency to 4.0.0-rc.1

## 0.5.0-pre.1 (December 19, 2022)

* Updated curve25519-dalek dependency to 4.0.0-pre.5

## 0.4.0 (September 15, 2022)

* Updated to be in sync with draft-irtf-cfrg-voprf-11, with
  the addition of the POPRF mode
* Adds the evaluate() function to the servers to calculate the output of the OPRF
  directly
* Renames the former evaluate() function to blind_evaluate to match the spec
* Fixes the order of parameters for PoprfClient::blind to align it with the
  other clients
* Exposes the derive_key function under the "danger" feature
* Added support for running the API without performing allocations
* Revamped the way the Group trait was used, so as to be more easily
  extendable to other groups
* Added common traits for each public-facing struct, including serde
  support

## 0.3.0 (October 25, 2021)

* Updated to be in sync with draft-irtf-cfrg-voprf-08

## 0.2.0 (October 18, 2021)

* Removed the CipherSuite interface
* Added the "danger" feature for exposing internal functions
* General improvements to the group interface

## 0.1.0 (September 29, 2021)

* Initial release
