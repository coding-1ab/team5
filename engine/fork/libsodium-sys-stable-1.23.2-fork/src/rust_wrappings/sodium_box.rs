use crate::sodium_bindings::{sodium_free, sodium_malloc, sodium_memzero};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use core::ptr::copy_nonoverlapping;
use secrecy::SecretBox;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct SodiumBox<T> {
    ptr: *mut T,
    len: usize, // It's Counts T, No Byte
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
        len *= (size_of::<T>() / size_of::<U>());
        SodiumBox::<U> { ptr, len } // todo!
    }
}
impl<T> Into<SecretBox<[T]>> for SodiumBox<T>
where
    [T]: Zeroize,
{
    fn into(self) -> SecretBox<[T]> {
        let mut boxed = Box::new_uninit_slice(self.len());
        self.copy_to(boxed.as_mut_ptr() as *mut T);
        let boxed_slice: Box<[T]> = unsafe { boxed.assume_init() };
        let _ = mem::ManuallyDrop::new(self);
        SecretBox::new(boxed_slice)
    }
}
impl<T> Into<Vec<T>> for SodiumBox<T>
where
    [T]: Zeroize,
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
impl<T> Zeroize for SodiumBox<T> {
    fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr.cast(), self.len * size_of::<T>());
        }
    }
}
impl<T> Drop for SodiumBox<T> {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast());
        }
    }
}
