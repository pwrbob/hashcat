use std::{ffi::c_int, slice};

pub unsafe fn vec_from_raw_parts<T: Clone>(data: *const T, length: c_int) -> Vec<T> {
    if data.is_null() {
        vec![]
    } else {
        Vec::from(unsafe { slice::from_raw_parts(data, length as usize) })
    }
}
