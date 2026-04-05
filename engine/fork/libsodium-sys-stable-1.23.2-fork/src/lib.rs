#![cfg_attr(not(any(feature = "wasi-component", feature = "wasmer-wai")), no_std)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)] // we can't control bindgen output to make clippy happy
#![allow(dead_code)]

extern crate alloc;
extern crate libc;

mod sodium_bindings;

use core::ffi::c_void;
use core::mem::transmute;
use libc::{c_int, ptrdiff_t};

/// Shared cryptographic implementations used by both WIT and WAI components
#[cfg(any(feature = "wasi-component", feature = "wasmer-wai"))]
pub mod crypto_impl;

#[cfg(all(feature = "wasi-component", target_arch = "wasm32"))]
mod component;

#[cfg(all(feature = "wasmer-wai", target_arch = "wasm32"))]
mod wai_component;

pub mod rust_wrappings;
