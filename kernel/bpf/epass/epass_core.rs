// SPDX-License-Identifier: GPL-2.0-only
//! GENERATED from the ePass repository (core-rs/epass-core, 4b4100a) by
//! kernel/sync-core.sh. Do not edit; change epass-core instead.
#![allow(missing_docs, unreachable_pub, rust_2018_idioms, dead_code)]
#![allow(clippy::all, clippy::undocumented_unsafe_blocks, clippy::ptr_as_ptr)]
#![allow(clippy::cast_lossless, clippy::as_underscore, clippy::ref_as_ptr)]
#![allow(clippy::ptr_cast_constness, clippy::as_ptr_cast_mut)]
//! ePass v2 core.
//!
//! An SSA compiler for eBPF programs that runs unchanged in userspace and in
//! the Linux kernel. The crate is `no_std`, has no dependencies, and never
//! panics or recurses in proportion to its input: every allocation is
//! fallible, every lookup is checked, and every graph walk uses an explicit
//! worklist. The only platform contact is the [`mem::Host`] trait.
//!
//! See `design.md` at the repository root.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

#[cfg(test)]
extern crate std;

pub mod analysis;
pub mod bin;
pub mod bpf;
pub mod cg;
pub mod ctx;
pub mod driver;
pub mod error;
pub mod facts;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod ir;
pub mod lift;
pub mod log;
pub mod mem;
pub mod passes;
pub mod pm;

pub use ctx::{Budget, Ctx, Limits};
pub use error::{Error, ErrorKind, Result};
pub use log::{Level, Log};
pub use mem::{Heap, Host};
