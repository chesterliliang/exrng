// This file is part of schnorrkel.
// Copyright (c) 2017-2019 Chester Li
// See LICENSE for licensing information.
//
// Authors:
// - Chester Li <chester@lichester.com>

//! # exrng
//! This crate has all features of CryptoRNG and RngCore
//! But just fill the rng buffer with external 32 bytes input
//! for platform without RUST rng supported
//! could saftisfy other crypto crate's need for RNG
//! so that crate could be compiled
//! BE SURE the input are real and good random number
//! 
//! simple calling example
//! let rng_bytes:[u8;32] = [1u8;32];
//! let mut rng = ExternalRng {rng_bytes,len:32};
//! let mut zero = [0u8; 32];
//!  rng.fill_bytes(&mut zero);
//! 
//! Here is a reference why we bring up this issue
//! in crate schnorrkel
//! Attach a `CryptoRng` to a `SigningTranscript` to repalce the default `ThreadRng`
//! There are tricks like `attach_rng(t,ChaChaRng::from_seed([0u8; 32]))`
//! for deterministic tests.  We warn against doing this in production
//! however because, although such derandomization produces secure Schnorr
//! signatures, we do implement protocols here like multi-signatures which
//! likely become vulnerabile when derandomized.
//! 
//! pub fn attach_rng<T,R>(t: T, rng: R) -> SigningTranscriptWithRng<T,R>
//! where T: SigningTranscript, R: RngCore+CryptoRng
//! {
//!     SigningTranscriptWithRng {
//!         t, rng: RefCell::new(rng)
//!     }
//! }
//! 
//! 
//! example for schnorrkel calling
//! let trng_bytes = slice::from_raw_parts(random, PUB_KEY_LEN);
//!	let signature: Signature = keypair.sign(
//!        attach_rng(
//!            context.bytes(&message_bytes[..]), 
//!            exrng::ExternalRng{
//!                rng_bytes:ExternalRng::copy_into_array(trng_bytes),
//!                len:32}
//!                ));
//! 
#![no_std]
#![warn(future_incompatible)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![deny(missing_docs)] // refuse to compile if documentation is missing

use rand_core::{CryptoRng,RngCore};

/// ExternalRng has all features
/// But use external random source
pub struct ExternalRng
{
    /// bytes to receive external rng when init
    pub rng_bytes: [u8;32],
    /// lenght of RNG
    pub len: usize
}
impl ExternalRng
{
    /// for fill_bytes to fill rng with bytes in struct element
    fn set_rng(&self, dest: &mut [u8])
    {
        let mut k = 0;
        while k<self.len
        {
            dest[k] = self.rng_bytes[k];
            k= k+1;
        }
    }
    /// for no std env
    /// if want to convert slice to array
    /// # Inputs
    /// * 'slice' is a slice from raw part
    /// # returns
    /// * array from slice
    /// 
    /// # Examples
    /// 
    /// ```
    /// use rand_core::{CryptoRng,RngCore};
    /// use exrng::ExternalRng;
    /// fn main(){
    /// use core::slice;
    /// let rng_bytes:[u8;32] = [1u8;32];
    /// let random_ptr: *const u8 = rng_bytes.as_ptr();
    /// let r:&[u8] = unsafe {slice::from_raw_parts(random_ptr, 32)};
    /// let mut rng = ExternalRng {rng_bytes:ExternalRng::copy_into_array(r),len:32};
    /// let mut zero = [0u8; 32];
    /// rng.fill_bytes(&mut zero);
    /// assert_eq!([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], &zero[..]);
    /// }
    /// ```
    pub fn copy_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Copy,
    {
        let mut a = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
        a
    }

}

impl RngCore for ExternalRng {
    fn next_u32(&mut self) -> u32 {  panic!()  }
    fn next_u64(&mut self) -> u64 {  panic!()  }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.set_rng(dest); 
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for ExternalRng {}



#[test]
fn should_work(){
    let rng_bytes:[u8;32] = [1u8;32];
    let mut rng = ExternalRng {rng_bytes,len:32};
    let mut zero = [0u8; 32];
    rng.fill_bytes(&mut zero);
    assert_eq!([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], &zero[..]);
}
