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

//! Emit the crate family's build version as `REFINEID_BUILD_VERSION`.
//!
//! The version is deterministic for anything that ships: a release build, or
//! any build with `SOURCE_DATE_EPOCH` set (Debian and Nix set it), reports the
//! bare workspace version, so the packaging system never invents a version and
//! reproducibility holds. Only a local debug build with no `SOURCE_DATE_EPOCH`
//! appends a `+B` build-metadata stamp, where B is the UTC hour times ten plus
//! the minute over ten -- a development convenience, never committed.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in one hour.
const SECONDS_PER_HOUR: u64 = 3_600;
/// Seconds in one minute.
const SECONDS_PER_MINUTE: u64 = 60;
/// Seconds in one day, for reducing an epoch to its time of day.
const SECONDS_PER_DAY: u64 = 86_400;
/// The hour's weight in the B stamp.
const HOUR_WEIGHT: u64 = 10;
/// The minute is counted in tens.
const MINUTES_PER_B_UNIT: u64 = 10;

fn main() {
    // A change to the reproducibility signal must re-run this script.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let is_debug = std::env::var("PROFILE").as_deref() == Ok("debug");
    let is_reproducible = std::env::var_os("SOURCE_DATE_EPOCH").is_some();

    let reported = if is_debug && !is_reproducible {
        match utc_b_stamp() {
            Some(b) => format!("{version}+{b}"),
            None => version,
        }
    } else {
        version
    };

    println!("cargo:rustc-env=REFINEID_BUILD_VERSION={reported}");
}

/// The current UTC B stamp (hour * 10 + minute / 10), or `None` if the host
/// clock is before the Unix epoch.
fn utc_b_stamp() -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let time_of_day = now % SECONDS_PER_DAY;
    let hour = time_of_day / SECONDS_PER_HOUR;
    let minute = (time_of_day % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
    Some(hour * HOUR_WEIGHT + minute / MINUTES_PER_B_UNIT)
}
