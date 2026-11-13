//! Library for tracking memory allocations
//!
//! The crate doesn't create a global allocator by itself. Each library (cdylib)
//! have to declare allocator by its own inside of the top-level crate and
//! create a method to interrogate allocator
//!
//! Example:
//! ```ignore
//! #[global_allocator]
//! static ALLOC: telio_memtrack::TrackingAllocator = telio_memtrack::TrackingAllocator::new();
//!
//! pub fn get_memory_usage() -> u64 {
//!     ALLOC.allocated()
//! }
//! ```
//!
//! Important notes:
//! * ONLY dynamic libraries (cdylib) may use it
//! * Every library has its own counter and counting its own memory
//! * Only Rust allocations are counted. Memory allocated by C#, GO or C code is NOT included
//! * All calls go to `System`, we only update the counter

#![deny(missing_docs)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Wrapper for System allocator that counts allocated bytes
#[derive(Debug, Default)]
pub struct TrackingAllocator {
    allocated: AtomicUsize,
}

impl TrackingAllocator {
    /// Creates a new allocator
    pub const fn new() -> Self {
        Self {
            allocated: AtomicUsize::new(0),
        }
    }

    /// Returns number of currently allocated bytes
    pub fn allocated(&self) -> u64 {
        self.allocated.load(Ordering::Relaxed) as u64
    }

    fn add(&self, size: usize) {
        self.allocated.fetch_add(size, Ordering::Relaxed);
    }

    fn sub(&self, size: usize) {
        self.allocated.fetch_sub(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        self.sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        // If realloc fails, the old block still will be there, so don't change the counter
        if !new_ptr.is_null() {
            let old_size = layout.size();
            if new_size >= old_size {
                self.add(new_size - old_size);
            } else {
                self.sub(old_size - new_size);
            }
        }
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test creates its own allocator inplace and calls it directly, not the global allocator

    // Prepare request for such big amount of memory that it will fail for sure on any machine
    // Only on 64-bit, on 32-bit it's about 1 GiB and could succeed
    #[cfg(target_pointer_width = "64")]
    const TOO_BIG: usize = isize::MAX as usize / 2;

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, 8).unwrap()
    }

    #[test]
    fn starts_at_zero() {
        assert_eq!(TrackingAllocator::new().allocated(), 0);
    }

    #[test]
    fn alloc_and_dealloc() {
        let a = TrackingAllocator::new();
        unsafe {
            let p = a.alloc(layout(100));
            assert!(!p.is_null());
            assert_eq!(a.allocated(), 100);
            let q = a.alloc(layout(28));
            assert_eq!(a.allocated(), 128);
            a.dealloc(p, layout(100));
            assert_eq!(a.allocated(), 28);
            a.dealloc(q, layout(28));
        }
        assert_eq!(a.allocated(), 0);
    }

    #[test]
    fn alloc_zeroed_is_counted_and_zeroed() {
        let a = TrackingAllocator::new();
        unsafe {
            let p = a.alloc_zeroed(layout(64));
            assert!(!p.is_null());
            assert_eq!(a.allocated(), 64);
            assert!(std::slice::from_raw_parts(p, 64).iter().all(|&b| b == 0));
            a.dealloc(p, layout(64));
        }
        assert_eq!(a.allocated(), 0);
    }

    #[test]
    fn realloc_grow_and_shrink() {
        let a = TrackingAllocator::new();
        unsafe {
            let p = a.alloc(layout(16));
            let p = a.realloc(p, layout(16), 4096);
            assert!(!p.is_null());
            assert_eq!(a.allocated(), 4096);
            let p = a.realloc(p, layout(4096), 8);
            assert!(!p.is_null());
            assert_eq!(a.allocated(), 8);
            a.dealloc(p, layout(8));
        }
        assert_eq!(a.allocated(), 0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn failed_allocations_are_not_counted() {
        let a = TrackingAllocator::new();
        unsafe {
            assert!(a.alloc(layout(TOO_BIG)).is_null());
            assert!(a.alloc_zeroed(layout(TOO_BIG)).is_null());
        }
        assert_eq!(a.allocated(), 0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn failed_realloc_keeps_original_size() {
        let a = TrackingAllocator::new();
        unsafe {
            let p = a.alloc(layout(32));
            assert!(!p.is_null());
            assert!(a.realloc(p, layout(32), TOO_BIG).is_null());
            assert_eq!(a.allocated(), 32);
            // Old block is still valid after failed realloc
            a.dealloc(p, layout(32));
        }
        assert_eq!(a.allocated(), 0);
    }
}
