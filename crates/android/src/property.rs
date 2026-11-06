/// Android system properties (`ro.build.version.sdk` and so on).
pub struct SystemProperty;

#[cfg(target_os = "android")]
unsafe extern "C" {
    /// Declared in `<sys/system_properties.h>` of bionic. The value buffer must hold
    /// `PROP_VALUE_MAX` (92) bytes; values of read-only properties may be longer and are
    /// truncated, which is fine for the short properties read here.
    pub fn __system_property_get(name: *const std::ffi::c_char, value: *mut std::ffi::c_char) -> std::ffi::c_int;
    /// Declared in `<sys/system_properties.h>` of bionic. Returns 0 on success.
    pub fn __system_property_set(name: *const std::ffi::c_char, value: *const std::ffi::c_char) -> std::ffi::c_int;
}

impl SystemProperty {
    pub const VALUE_MAX: usize = 92;
    pub const SDK: &'static str = "ro.build.version.sdk";
    pub const RELEASE: &'static str = "ro.build.version.release";
    pub const BOOT_COMPLETED: &'static str = "sys.boot_completed";

    /// Reads a property. Returns `None` if it is unset or empty, or on systems other than Android.
    pub fn get(name: &str) -> Option<String> {
        #[cfg(target_os = "android")]
        {
            let name = std::ffi::CString::new(name).ok()?;
            let mut value = [0 as std::ffi::c_char; SystemProperty::VALUE_MAX];
            // SAFETY: `name` is NUL-terminated and `value` has the size bionic requires.
            let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
            if length <= 0 {
                return None;
            }
            let bytes: Vec<u8> = value[..length as usize].iter().map(|byte| *byte as u8).collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = name;
            None
        }
    }

    /// Sets a property through the property service of init. Init decides whether the
    /// caller may set it; `ctl.*` properties ask init to start, stop or restart a service.
    pub fn set(name: &str, value: &str) -> std::io::Result<()> {
        #[cfg(target_os = "android")]
        {
            let invalid = |_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "property contains a NUL byte");
            let name = std::ffi::CString::new(name).map_err(invalid)?;
            let value = std::ffi::CString::new(value).map_err(invalid)?;
            // SAFETY: both strings are NUL-terminated.
            match unsafe { __system_property_set(name.as_ptr(), value.as_ptr()) } {
                0 => Ok(()),
                _ => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "the property service refused the property")),
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (name, value);
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "system properties require Android"))
        }
    }

    /// The API level of the running system.
    pub fn sdk() -> Option<u32> {
        SystemProperty::get(SystemProperty::SDK)?.trim().parse().ok()
    }

    /// Whether the system has finished booting (`sys.boot_completed` is `1`).
    pub fn is_boot_completed() -> bool {
        SystemProperty::get(SystemProperty::BOOT_COMPLETED).is_some_and(|value| value.trim() == "1")
    }
}
