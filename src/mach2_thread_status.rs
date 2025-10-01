//! This module corresponds to `mach/thread_status.h`.
// A copy of mach2 without the target defines so that it is usable

use mach2::vm_types::natural_t;

pub type thread_state_t = *mut natural_t;
pub type thread_state_flavor_t = u32;

mod aarch64 {
    use super::thread_state_flavor_t;

    pub const ARM_THREAD_STATE: thread_state_flavor_t = 1;
    pub const ARM_UNIFIED_THREAD_STATE: thread_state_flavor_t = ARM_THREAD_STATE;
    pub const ARM_VFP_STATE: thread_state_flavor_t = 2;
    pub const ARM_EXCEPTION_STATE: thread_state_flavor_t = 3;
    pub const ARM_DEBUG_STATE: thread_state_flavor_t = 4;
    pub const ARM_THREAD_STATE_NONE: thread_state_flavor_t = 5;
    pub const ARM_THREAD_STATE64: thread_state_flavor_t = 6;
    pub const ARM_EXCEPTION_STATE64: thread_state_flavor_t = 7;
    pub const ARM_DEBUG_STATE32: thread_state_flavor_t = 14;
    pub const ARM_DEBUG_STATE64: thread_state_flavor_t = 15;
    pub const ARM_NEON_STATE: thread_state_flavor_t = 16;
    pub const ARM_NEON_STATE64: thread_state_flavor_t = 17;
    pub const ARM_CPMU_STATE64: thread_state_flavor_t = 18;
}

pub use self::aarch64::*;

mod x86_64 {
    use super::thread_state_flavor_t;

    pub const x86_THREAD_STATE32: thread_state_flavor_t = 1;
    pub const x86_FLOAT_STATE32: thread_state_flavor_t = 2;
    pub const x86_EXCEPTION_STATE32: thread_state_flavor_t = 3;
    pub const x86_THREAD_STATE64: thread_state_flavor_t = 4;
    pub const x86_FLOAT_STATE64: thread_state_flavor_t = 5;
    pub const x86_EXCEPTION_STATE64: thread_state_flavor_t = 6;
    pub const x86_THREAD_STATE: thread_state_flavor_t = 7;
    pub const x86_FLOAT_STATE: thread_state_flavor_t = 8;
    pub const x86_EXCEPTION_STATE: thread_state_flavor_t = 9;
    pub const x86_DEBUG_STATE32: thread_state_flavor_t = 10;
    pub const x86_DEBUG_STATE64: thread_state_flavor_t = 11;
    pub const x86_DEBUG_STATE: thread_state_flavor_t = 12;
    pub const x86_THREAD_STATE_NONE: thread_state_flavor_t = 13;
    pub const x86_AVX_STATE32: thread_state_flavor_t = 16;
    pub const x86_AVX_STATE64: thread_state_flavor_t = 17;
    pub const x86_AVX_STATE: thread_state_flavor_t = 18;
}

pub use self::x86_64::*;
