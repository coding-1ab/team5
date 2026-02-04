extern crate core;

use core::panic::const_assert;
use single_instance::SingleInstance;

fn main() -> std::io::Result<()> {
    let instance = SingleInstance::new("team5");
    if !instance.unwrap().is_single() {
        return Ok(())
    }

    let s = core::mem::size_of::<usize>();
    let mut arr1 = [0u8];
    arr1[s-8] = 1;


    Ok(())
}