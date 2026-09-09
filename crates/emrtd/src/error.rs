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

//! Error types for ICAO 9303 eMRTD application operations.

use core::fmt;

use refineid_apdu::{CommandDataError, StatusWord, TransportOutcome};

/// Failures that can occur during eMRTD application operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmrtdError<TransportError> {
    /// Transport-level fault when communicating with the card.
    Transport(TransportError),
    /// The card slot is empty or the card was removed.
    NoCard,
    /// Protocol synchronization was lost.
    ProtocolDesync,
    /// Card timed out in an indeterminate state.
    TimeoutUnknownState,
    /// Card performed an unexpected reset.
    CardReset,
    /// Reader was unplugged or terminated.
    ReaderRemoved,
    /// The card returned an unexpected or error status word.
    Status {
        /// The operation that failed.
        operation: &'static str,
        /// The status word returned by the card.
        sw: StatusWord,
    },
    /// Command construction or data validation failure.
    Command(CommandDataError),
    /// Outer ASN.1/TLV parsing failure.
    MalformedData,
    /// The requested elementary file was empty or absent.
    EmptyFile,
}

impl<E: fmt::Display> fmt::Display for EmrtdError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "transport error: {err}"),
            Self::NoCard => f.write_str("card is not present in the field"),
            Self::ProtocolDesync => f.write_str("protocol desynchronization with card"),
            Self::TimeoutUnknownState => f.write_str("timeout while card in unknown state"),
            Self::CardReset => f.write_str("card reset during operation"),
            Self::ReaderRemoved => f.write_str("reader was removed"),
            Self::Status { operation, sw } => {
                write!(f, "card rejected {operation} with status {sw:?}")
            }
            Self::Command(err) => write!(f, "command construction error: {err}"),
            Self::MalformedData => f.write_str("malformed ASN.1/TLV data in response"),
            Self::EmptyFile => f.write_str("elementary file is empty or not found"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for EmrtdError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transport(err) => Some(err),
            Self::Command(err) => Some(err),
            _ => None,
        }
    }
}

impl<E> From<TransportOutcome> for EmrtdError<E> {
    fn from(outcome: TransportOutcome) -> Self {
        match outcome {
            TransportOutcome::Response(_) => Self::MalformedData,
            TransportOutcome::NoCard => Self::NoCard,
            TransportOutcome::TimeoutUnknownState => Self::TimeoutUnknownState,
            TransportOutcome::CardReset => Self::CardReset,
            TransportOutcome::ProtocolDesync => Self::ProtocolDesync,
            TransportOutcome::ReaderRemoved => Self::ReaderRemoved,
        }
    }
}
