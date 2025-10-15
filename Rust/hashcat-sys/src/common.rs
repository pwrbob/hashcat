use std::{
    ffi::{c_char, c_int, CStr},
    slice,
};

/// convert an array of data of a given type T to a Vec<T>
pub unsafe fn vec_from_raw_parts<T: Clone>(data: *const T, length: c_int) -> Vec<T> {
    if data.is_null() {
        vec![]
    } else {
        Vec::from(unsafe { slice::from_raw_parts(data, length as usize) })
    }
}

/// convert a C char* to a Rust String
pub unsafe fn string_from_ptr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().unwrap_or_default().to_string() }
    }
}
