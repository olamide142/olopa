//! OpenSSL encryption uprobes — hooks on EVP_EncryptUpdate and EVP_DecryptUpdate.
//!
//! These are the inner work-horse functions called once per chunk by OpenSSL's
//! symmetric cipher engine.  Hooking them gives per-call byte-count telemetry
//! without reading plaintext or key material.
//!
//! Signatures:
//!   int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//!                         int *outl, const unsigned char *in, int inl)
//!   int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//!                         int *outl, const unsigned char *in, int inl)
//!
//! arg index 4 (`inl`) = number of input bytes for this call.
//!
//! Ransomware detection relies on correlating a high sustained byte-count from
//! EVP_EncryptUpdate calls with concurrent file-write activity on the same PID,
//! which the OIL rule engine can express as a `correlate` rule.
//!
//! VERIFIER RULE: after bpf_ringbuf_reserve() succeeds, every exit path must
//! call entry.submit(0) or entry.discard(0). Never use ? after reservation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::uprobe,
    programs::ProbeContext,
};
use olopa_common::{SslEvent, EVENT_KIND_SSL};

use crate::EVENTS;

/// Uprobe on libssl `EVP_EncryptUpdate`.
/// Fires on each symmetric encryption chunk. operation = 0.
#[uprobe]
pub fn uprobe_evp_encrypt_update(ctx: ProbeContext) -> u32 {
    unsafe { try_ssl_event(&ctx, 0) }
}

/// Uprobe on libssl `EVP_DecryptUpdate`.
/// Fires on each symmetric decryption chunk. operation = 1.
#[uprobe]
pub fn uprobe_evp_decrypt_update(ctx: ProbeContext) -> u32 {
    unsafe { try_ssl_event(&ctx, 1) }
}

/// Common handler for both SSL uprobes.
///
/// Reads `inl` (arg index 4) as the byte-count for this cipher call and
/// emits a `SslEvent` to the shared ring buffer.
///
/// # Arguments
/// * `operation` — 0 for encrypt, 1 for decrypt.
unsafe fn try_ssl_event(ctx: &ProbeContext, operation: u8) -> u32 {
    let mut entry = match EVENTS.reserve::<SslEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After reservation every exit path must submit or discard.
    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_SSL;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    (*event).comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // EVP_{Encrypt,Decrypt}Update arg 4 = `int inl` (input byte count).
    // Cast through i32 first to respect C int signedness, then to u32.
    let inl: i32 = match ctx.arg(4_usize) {
        Some(v) => v,
        None => {
            entry.discard(0);
            return 1;
        }
    };
    (*event).data_len = if inl > 0 { inl as u32 } else { 0 };
    (*event).operation = operation;
    (*event)._pad = [0u8; 3];

    entry.submit(0);
    0
}
