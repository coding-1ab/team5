use crate::sodium_bindings;

pub fn sodium_init() -> Result<(), ()> {
    unsafe {
        if sodium_bindings::sodium_init() != 0 {
            return Err(())
        }
    }
    Ok(())
}
