// SPDX-License-Identifier: MIT

//! Helpers for the AmneziaWG 3.0 `u32_range_t` wire format.
//!
//! Since kernel module v3.0 the magic header attributes
//! (`WGDEVICE_A_H1`..`WGDEVICE_A_H4`) are transferred as a `u64` packing a
//! range of `u32` values: the low 32 bits hold the range start, the high 32
//! bits hold the range end. Older modules (genl family version 2) transfer
//! the same information as a NUL-terminated decimal string, either `"<v>"`
//! or `"<lo>-<hi>"`. These helpers convert between the two representations.

/// Packs a `[lo, hi]` `u32` range into the `u64` wire value used by the
/// AmneziaWG 3.0 kernel module.
pub fn u32_range_pack(lo: u32, hi: u32) -> u64 {
    ((hi as u64) << 32) | (lo as u64)
}

/// Unpacks the `u64` wire value into `(lo, hi)`.
pub fn u32_range_unpack(range: u64) -> (u32, u32) {
    (range as u32, (range >> 32) as u32)
}

/// Formats a packed range the way `awg`(8) and the v1.0 kernel module do:
/// `"<lo>"` when `lo == hi`, `"<lo>-<hi>"` otherwise.
pub fn u32_range_to_string(range: u64) -> String {
    let (lo, hi) = u32_range_unpack(range);
    if lo == hi {
        lo.to_string()
    } else {
        format!("{lo}-{hi}")
    }
}

/// Parses a magic header spec string (`"<v>"` or `"<lo>-<hi>"`) into the
/// packed `u64` wire value. Returns `None` for malformed input or when
/// `lo > hi`.
pub fn u32_range_from_string(spec: &str) -> Option<u64> {
    let mut parts = spec.splitn(2, '-');
    let lo: u32 = parts.next()?.trim().parse().ok()?;
    let hi: u32 = match parts.next() {
        Some(s) => s.trim().parse().ok()?,
        None => lo,
    };
    if lo > hi {
        return None;
    }
    Some(u32_range_pack(lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let v = u32_range_pack(61220074, 118999195);
        assert_eq!(u32_range_unpack(v), (61220074, 118999195));
        assert_eq!(u32_range_unpack(u32_range_pack(5, 5)), (5, 5));
    }

    #[test]
    fn to_string_formats() {
        assert_eq!(u32_range_to_string(u32_range_pack(25, 25)), "25");
        assert_eq!(
            u32_range_to_string(u32_range_pack(61220074, 118999195)),
            "61220074-118999195"
        );
    }

    #[test]
    fn from_string_parses() {
        assert_eq!(u32_range_from_string("25"), Some(u32_range_pack(25, 25)));
        assert_eq!(
            u32_range_from_string("61220074-118999195"),
            Some(u32_range_pack(61220074, 118999195))
        );
        assert_eq!(u32_range_from_string("bad"), None);
        assert_eq!(u32_range_from_string("10-5"), None);
        assert_eq!(u32_range_from_string(""), None);
    }
}
