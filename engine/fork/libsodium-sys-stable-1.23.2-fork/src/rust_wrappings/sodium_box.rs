use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::sodium_bindings::{sodium_free, sodium_malloc,};
use core::{mem};
use core::arch::x86_64::_mm_clflush;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{fence, Ordering};
use secrecy::SecretBox;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct SodiumBox<T> {
    ptr: *mut T,
    len: usize, // It's Counts T, Not Byte
}
impl<T> SodiumBox<T> {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn new_with_size(len: usize) -> SodiumBox<T> {
        let ptr: *mut T = unsafe { sodium_malloc(len * size_of::<T>()).cast() };
        Self { ptr, len }
    }
    pub fn from_raw(src: *const T, len: usize) -> SodiumBox<T> {
        unsafe {
            let ptr: *mut T = sodium_malloc(size_of::<T>() * len).cast();

            ptr.copy_from_nonoverlapping(src, len);

            Self { ptr, len }
        }
    }
    pub fn from_slice(s: &[T]) -> SodiumBox<T> {
        unsafe {
            let ptr: *mut T = sodium_malloc(s.len() * size_of::<T>()).cast();

            ptr.copy_from_nonoverlapping(s.as_ptr(), s.len());

            Self { ptr, len: s.len() }
        }
    }
    pub fn copy_to(&self, ptr: *mut T) {
        unsafe {
            copy_nonoverlapping(self.ptr, ptr, self.len);
        }
    }
    pub fn as_ptr(&self) -> *const T {
        self.ptr.cast_const()
    }
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }
    pub fn cast<U>(self) -> SodiumBox<U> {
        let ptr: *mut U = self.ptr.cast();
        let mut len = self.len;
        let _ = mem::ManuallyDrop::new(self);
        const { assert!(size_of::<T>() % size_of::<U>() == 0) }
        len *= size_of::<T>() / size_of::<U>();
        SodiumBox::<U> { ptr, len } // todo!
    }
}
impl<T> Into<SecretBox<[T]>> for SodiumBox<T> where [T]: Zeroize
{
    fn into(self) -> SecretBox<[T]> {
        let mut boxed = Box::new_uninit_slice(self.len());
        self.copy_to(boxed.as_mut_ptr() as *mut T);
        let boxed_slice: Box<[T]> = unsafe { boxed.assume_init() };
        SecretBox::new(boxed_slice)
    }
}
impl<T> Into<Vec<T>> for SodiumBox<T> where [T]: Zeroize,
{
    fn into(self) -> Vec<T> {
        let mut v = Vec::with_capacity(self.len);
        unsafe {
            v.set_len(self.len);
        }
        let p = v.as_mut_ptr();
        self.copy_to(p);
        v
    }
}
impl<T> Drop for SodiumBox<T> {
    fn drop(&mut self) {
        unsafe {
            let mut curr = self.ptr as usize;
            let end = curr + self.len * size_of::<T>();
            while curr < end {
                _mm_clflush(curr as *const u8);
                curr += 64;
            }

            sodium_free(self.ptr.cast());
            
            fence(Ordering::SeqCst);
        }
    }
}
