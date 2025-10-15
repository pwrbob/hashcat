#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
#[rustfmt::skip]
pub mod bindings;

/// common functions that are useful in Rust bridge implementations
pub mod common;

pub use bindings::{bridge_context_t, generic_io_t, generic_io_tmp_t, salt_t};
pub use common::*;

#[cfg(test)]
mod test {
    use super::*;

    /// test that bindings.rs exists by asserting some very basic things
    #[test]
    fn test_bindings_exists() {
        let ctx = bindings::generic_io_t {
            hash_buf: [0; 256],
            hash_len: 0,
            salt_buf: [0; 256],
            salt_len: 0,
        };
        assert_eq!(ctx.hash_len, 0);
        assert_eq!(ctx.salt_len, 0);
    }
}
