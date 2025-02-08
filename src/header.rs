#![allow(non_camel_case_types)]
pub type pid_t = libc::pid_t;
pub type c_int = libc::c_int;

pub mod glibc {
    use super::c_int;

    extern "C" {
        // const char *sigabbrev_np(int sig);
        pub fn sigabbrev_np(sig: c_int) -> *const libc::c_char;

        // const char *gnu_get_libc_version(void);
        pub fn gnu_get_libc_version() -> *const libc::c_char;
    }
}
