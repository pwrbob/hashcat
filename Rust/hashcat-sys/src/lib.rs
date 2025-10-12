#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
#[rustfmt::skip]
pub mod bindings;

pub use bindings::*;

#[cfg(test)]
mod test {
    use super::*;

    /// test that bindings.rs exists by asserting some very basic things
    #[test]
    fn test_bindings_exists() {
        assert_eq!(bindings::INT8_MIN, -128);
    }
}
