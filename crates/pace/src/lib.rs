// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Reviewed Card Access Number type.
//!
//! Values crossing a trust boundary are deconstructed, validated once, and
//! reconstructed as types whose constructors preserve their invariants.

pub mod can;

pub use can::{CAN_DIGITS, Can, CanError, UnvalidatedCan};

#[cfg(test)]
mod public_contract_tests {
    use core::fmt::Display;

    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{Can, UnvalidatedCan};

    trait AmbiguousIfImplemented<Disambiguator, Marker> {
        fn marker() {}
    }

    impl<T: ?Sized, Marker> AmbiguousIfImplemented<(), Marker> for T {}

    struct CloneMarker;
    impl<T: Clone> AmbiguousIfImplemented<bool, CloneMarker> for T {}

    struct CopyMarker;
    impl<T: Copy> AmbiguousIfImplemented<bool, CopyMarker> for T {}

    struct ZeroizeMarker;
    impl<T: ?Sized + Zeroize> AmbiguousIfImplemented<bool, ZeroizeMarker> for T {}

    struct SerializeMarker;
    impl<T: ?Sized + Serialize> AmbiguousIfImplemented<bool, SerializeMarker> for T {}

    struct DeserializeMarker;
    impl<T: DeserializeOwned> AmbiguousIfImplemented<bool, DeserializeMarker> for T {}

    struct DisplayMarker;
    impl<T: ?Sized + Display> AmbiguousIfImplemented<bool, DisplayMarker> for T {}

    fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    fn require_zeroizable_boundary<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn sensitive_public_types_preserve_ownership_contracts() {
        require_zeroize_on_drop::<Can>();
        require_zeroizable_boundary::<UnvalidatedCan>();

        let _ = <Can as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, DisplayMarker>>::marker;
    }
}
