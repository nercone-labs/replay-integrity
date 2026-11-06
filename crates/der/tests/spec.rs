//! Tests of the DER reader against ITU-T X.690 and the encodings certificates use. The test
//! vectors are built here from the standard, not copied from this reader's output.

use der::{DERError, Element, Integer, ObjectIdentifier, Reader, Tag, TagClass, Time};

#[test]
fn lengths_use_the_shortest_definite_form() {
    // 8.1.3: short form below 128, long form above, never indefinite.
    assert_eq!(Reader::parse_length(&[0x00]), Ok((0, 1)));
    assert_eq!(Reader::parse_length(&[0x7f]), Ok((127, 1)));
    assert_eq!(Reader::parse_length(&[0x81, 0x80]), Ok((128, 2)));
    assert_eq!(Reader::parse_length(&[0x82, 0x01, 0x00]), Ok((256, 3)));
    // 128 must use the long form's single byte, not 0x7f short form boundary.
    assert_eq!(Reader::parse_length(&[0x81, 0x7f]), Err(DERError::InvalidLength));
    assert_eq!(Reader::parse_length(&[0x82, 0x00, 0xff]), Err(DERError::InvalidLength));
    assert_eq!(Reader::parse_length(&[0x80]), Err(DERError::IndefiniteLength));
}

#[test]
fn tags_decode_both_forms() {
    // 8.1.2: low tag numbers in one byte, high tag numbers in the following form.
    let (tag, length) = Reader::parse_tag(&[0x02]).unwrap();
    assert_eq!((tag, length), (Tag::INTEGER, 1));
    let (sequence, _) = Reader::parse_tag(&[0x30]).unwrap();
    assert_eq!(sequence, Tag::SEQUENCE);
    assert!(sequence.constructed);
    // [705] EXPLICIT is 0xbf 0x85 0x41 (context, constructed, number 705).
    let (high, length) = Reader::parse_tag(&[0xbf, 0x85, 0x41]).unwrap();
    assert_eq!((high.class, high.constructed, high.number, length), (TagClass::ContextSpecific, true, 705, 3));
    // A leading 0x80 in the high form is not the shortest encoding.
    assert_eq!(Reader::parse_tag(&[0x1f, 0x80, 0x01]), Err(DERError::InvalidTag));
    // Numbers below 31 must use the short form.
    assert_eq!(Reader::parse_tag(&[0x1f, 0x1e]), Err(DERError::InvalidTag));
    // An overlong high-tag encoding whose value exceeds the limit is rejected, not wrapped:
    // 0x1f 0xc0 0x80 0x80 0x80 0x3f would wrap a u32 if checked after shifting.
    assert_eq!(Reader::parse_tag(&[0x1f, 0xc0, 0x80, 0x80, 0x80, 0x3f]), Err(DERError::InvalidTag));
}

#[test]
fn integers_are_minimal_twos_complement() {
    assert_eq!(Integer::new(&[0x00]).unwrap().to_u64(), Some(0));
    assert_eq!(Integer::new(&[0x7f]).unwrap().to_i64(), Some(127));
    assert_eq!(Integer::new(&[0x00, 0x80]).unwrap().to_u64(), Some(128));
    assert_eq!(Integer::new(&[0xff]).unwrap().to_i64(), Some(-1));
    assert_eq!(Integer::new(&[0x80]).unwrap().to_i64(), Some(-128));
    // Non-minimal encodings are rejected (8.3.2).
    assert_eq!(Integer::new(&[0x00, 0x00]), Err(DERError::InvalidValue("an INTEGER is not minimal")));
    assert_eq!(Integer::new(&[0xff, 0x80]), Err(DERError::InvalidValue("an INTEGER is not minimal")));
    assert_eq!(Integer::new(&[]), Err(DERError::InvalidValue("an INTEGER has no contents")));
    // Serial numbers are shown in lowercase hexadecimal without leading zeros.
    assert_eq!(Integer::new(&[0x00, 0xf9, 0x20, 0x09]).unwrap().to_hex().as_deref(), Some("f92009"));
    assert_eq!(Integer::new(&[0x00]).unwrap().to_hex().as_deref(), Some("0"));
    assert_eq!(Integer::new(&[0xff]).unwrap().to_hex(), None);
}

#[test]
fn object_identifiers_combine_the_first_two_arcs() {
    // 8.19.4: the first octet is 40*first + second. 1.2.840.113549 is RSA.
    let rsa = ObjectIdentifier::decode(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]).unwrap();
    assert!(rsa.is(&[1, 2, 840, 113549]));
    assert_eq!(rsa.to_string(), "1.2.840.113549");
    // 2.5.4.3 is the common name attribute; first octet 0x55 = 85 = 80 + 5.
    let cn = ObjectIdentifier::decode(&[0x55, 0x04, 0x03]).unwrap();
    assert!(cn.is(&[2, 5, 4, 3]));
    // A non-minimal arc (leading 0x80) is rejected.
    assert!(ObjectIdentifier::decode(&[0x80, 0x01]).is_err());
    assert!(ObjectIdentifier::decode(&[]).is_err());
}

#[test]
fn booleans_are_only_zero_or_all_ones() {
    // 11.1: DER encodes TRUE as 0xff.
    assert_eq!(Element::parse(&[0x01, 0x01, 0x00]).unwrap().boolean(), Ok(false));
    assert_eq!(Element::parse(&[0x01, 0x01, 0xff]).unwrap().boolean(), Ok(true));
    assert_eq!(Element::parse(&[0x01, 0x01, 0x01]).unwrap().boolean(), Err(DERError::InvalidValue("a BOOLEAN is not 0x00 or 0xff")));
}

#[test]
fn bit_strings_report_unused_bits() {
    // 8.6: the first contents octet is the number of unused bits in the last octet.
    let element = Element::parse(&[0x03, 0x02, 0x00, 0xff]).unwrap();
    let bits = element.bit_string().unwrap();
    assert_eq!((bits.unused_bits, bits.bytes), (0, &[0xff][..]));
    // Unused bits must be zero.
    assert!(Element::parse(&[0x03, 0x02, 0x01, 0xff]).unwrap().bit_string().is_err());
    // More than seven unused bits is invalid.
    assert!(Element::parse(&[0x03, 0x02, 0x08, 0x00]).unwrap().bit_string().is_err());
}

#[test]
fn times_are_parsed_as_utc_seconds() {
    // 11.8: UTCTime YYMMDDHHMMSSZ, with the RFC 5280 century rule.
    assert_eq!(Time::from_utc_time(b"700101000000Z").unwrap().seconds, 0);
    assert_eq!(Time::from_utc_time(b"490101000000Z").unwrap().seconds, Time::days_from_civil(2049, 1, 1) * 86_400);
    assert_eq!(Time::from_utc_time(b"500101000000Z").unwrap().seconds, Time::days_from_civil(1950, 1, 1) * 86_400);
    // 11.7: GeneralizedTime YYYYMMDDHHMMSSZ.
    assert_eq!(
        Time::from_generalized_time(b"20260206123456Z").unwrap(),
        Time { seconds: Time::days_from_civil(2026, 2, 6) * 86_400 + 12 * 3600 + 34 * 60 + 56 }
    );
    // The forms DER forbids (fractions, offsets, missing seconds) are rejected.
    assert!(Time::from_utc_time(b"7001010000Z").is_err());
    assert!(Time::from_generalized_time(b"20260206123456+0000").is_err());
    assert!(Time::from_utc_time(b"700230000000Z").is_err());
}

#[test]
fn civil_day_conversion_round_trips() {
    for &(year, month, day) in &[(1970, 1, 1), (2000, 2, 29), (2026, 2, 6), (2042, 3, 15), (1950, 12, 31)] {
        let days = Time::days_from_civil(year, month, day);
        assert_eq!(Time::civil_from_days(days), (year, month, day));
    }
    assert!(Time::is_leap_year(2000) && Time::is_leap_year(2024) && !Time::is_leap_year(1900) && !Time::is_leap_year(2026));
}

#[test]
fn a_sequence_reads_its_elements_in_order() {
    // SEQUENCE { INTEGER 1, BOOLEAN true }
    let sequence = Element::parse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff]).unwrap();
    assert_eq!(sequence.tag, Tag::SEQUENCE);
    let mut reader = sequence.reader().unwrap();
    assert_eq!(reader.expect(Tag::INTEGER).unwrap().integer().unwrap().to_u64(), Some(1));
    assert!(reader.expect(Tag::BOOLEAN).unwrap().boolean().unwrap());
    reader.finish().unwrap();
    // Trailing data after a parsed element is rejected.
    assert_eq!(Element::parse(&[0x01, 0x01, 0x00, 0x00]), Err(DERError::TrailingData));
    // A truncated element is rejected.
    assert_eq!(Element::parse(&[0x30, 0x06, 0x02, 0x01]), Err(DERError::Truncated));
}
