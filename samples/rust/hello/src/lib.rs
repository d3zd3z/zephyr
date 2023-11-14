#![no_std]

use core::ffi::c_char;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub fn foo() {
    unsafe {
        printf("Hello from Rust\n\0".as_ptr().cast());
    }
}

// Test something with some division to see what happens.
#[no_mangle]
extern "C" fn divide(a: u32, b: u32) -> u32 {
    a / b
}

extern "C" {
    /// Very simple binding to printf, no formatting, but should let us call it.
    fn printf(msg: *const c_char);
}
