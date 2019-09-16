//! Object ID (OID) representation

use std::borrow::Cow;
use std::fmt;

use std::str::FromStr;

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    /// Signalizes that the first or second component is too large.
    /// The first must be within the range 0 to 6 (inclusive).
    /// The second component must be less than 256 - 40 * first.
    FirstComponentsTooLarge,
    ParseIntError,
}

/// Object ID (OID) representation which can be relative or non-relative.
/// An example for an oid in string representation is "1.2.840.113549.1.1.5".
///
/// For non-relative oids restrictions apply to the first two components.
///
/// This library ships with a procedural macro `oid` which can be used to
/// create oids. For example `oid!(1.2.44.233)` or `oid!(44.233)`
/// for relative oids.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Oid<'a> {
    asn1: Cow<'a, [u8]>,
    pub relative: bool,
}

fn encode_relative<'a>(ids: &'a [u64]) -> impl Iterator<Item=u8> + 'a {
    ids.iter()
        .map(|id| {
            let bit_count = 64 - id.leading_zeros();
            let octets_needed = ((bit_count + 6) / 7).max(1);
            (0..octets_needed).map(move |i| {
                let flag = if i == octets_needed - 1 { 0 } else { 1 << 7 };
                ((id >> 7 * (octets_needed - 1 - i)) & 0b111_1111) as u8 | flag
            })
        })
        .flatten()
}

impl<'a> Oid<'a> {
    /// Create an OID from the ASN.1 encoded form.
    pub fn new(asn1: Cow<'a, [u8]>) -> Oid {
        Oid { asn1, relative: false }
    }

    /// Create a relative OID from the ASN.1 encoded form.
    pub fn new_relative(asn1: Cow<'a, [u8]>) -> Oid {
        Oid { asn1, relative: true }
    }

    /// Build an OID from an array of object identifier components.
    pub fn from<'b>(s: &'b [u64]) -> Result<Oid<'static>, ParseError> {
        if s.len() < 2 {
            if s.len() == 1 && s[0] == 0 {
                return Ok(Oid { asn1: Cow::Borrowed(&[0]), relative: false });
            }
            return Err(ParseError::TooShort);
        }
        if s[0] >= 7 || s[1] >= 40 {
            return Err(ParseError::FirstComponentsTooLarge);
        }

        let asn1_encoded: Vec<u8> = 
            [(s[0] * 40 + s[1]) as u8].iter()
                .map(|o| *o)
                .chain(encode_relative(&s[2..]))
                .collect();
        Ok(Oid { asn1: Cow::from(asn1_encoded), relative: false })
    }

    /// Build a relative OID from an array of object identifier components.
    pub fn from_relative<'b>(s: &'b [u64]) -> Result<Oid<'static>, ParseError> {
        if s.is_empty() {
            return Err(ParseError::TooShort);
        }
        let asn1_encoded: Vec<u8> = encode_relative(s).collect();
        Ok(Oid { asn1: Cow::from(asn1_encoded), relative: true })
    }
    
    /// Create a deep copy of the oid.
    ///
    /// This method allocates data on the heap. The returned oid
    /// can be used without keeping the ASN.1 representing around.
    ///
    /// Cloning the returned oid does again allocate data.
    pub fn to_owned(&self) -> Oid<'static> {
        Oid { asn1: Cow::from(self.asn1.to_vec()), relative: self.relative }
    }
}

#[cfg(feature = "bigint")]
pub mod bigint {
    use num_bigint::BigUint;
    use std::iter::{Iterator, FusedIterator, ExactSizeIterator};

    impl<'a> crate::oid::Oid<'a> {
        /// Convert the OID to a string representation.
        /// The string contains the IDs separated by dots, for ex: "1.2.840.113549.1.1.5"
        pub fn to_string(&self) -> String {
            let ints: Vec<String> = self.iter().map(|i| i.to_string()).collect();
            ints.join(".")
        }

        /// Return an iterator over the sub-identifiers (arcs).
        #[cfg(feature = "bigint")]
        pub fn iter(&self) ->  SubIdentifierIterator {
            SubIdentifierIterator { oid: &self, pos: 0, first: false }
        }
    }

    pub struct SubIdentifierIterator<'a> {
        oid: &'a crate::oid::Oid<'a>,
        pos: usize,
        first: bool,
    }

    impl<'a> Iterator for SubIdentifierIterator<'a> {
        type Item = BigUint;

        fn next(&mut self) -> Option<Self::Item> {
            use num_traits::identities::Zero;

            if self.pos == self.oid.asn1.len() {
                return None;
            }
            if !self.oid.relative {
                if !self.first {
                    debug_assert!(self.pos == 0);
                    self.first = true;
                    return Some((self.oid.asn1[0] / 40).into());
                } else if self.pos == 0 {
                    self.pos += 1;
                    if self.oid.asn1[0] == 0 {
                        return None;
                    }
                    return Some((self.oid.asn1[0] % 40).into());
                }
            }
            // decode objet sub-identifier according to the asn.1 standard
            let mut res = BigUint::zero();
            for o in self.oid.asn1[self.pos..].into_iter() {
                self.pos += 1;
                res = (res << 7) + (o & 0b111_1111);
                let flag = o >> 7;
                if flag == 0u8 {
                    break;
                }
            }
            Some(res)
        }
    }

    impl<'a> FusedIterator for SubIdentifierIterator<'a> { } 

    impl<'a> ExactSizeIterator for SubIdentifierIterator<'a> {
        fn len(&self) -> usize {
            if self.oid.relative {
                self.oid.asn1.into_iter().filter(|o| (*o >> 7) == 0u8).count()
            } else {
                2 + self.oid.asn1[2..].into_iter().filter(|o| (*o >> 7) == 0u8).count() 
            }
        }

        // fn is_empty(&self) -> bool { self.oid.asn1.is_empty() }
    }
}

impl<'a> fmt::Display for Oid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(feature = "bigint") {
            if self.relative {
                f.write_str("rel. ")?;
            }
            f.write_str(&self.to_string())
        } else {
            f.write_str("ASN.1 ")?;
            if self.relative {
                f.write_str("rel. ")?;
            }
            let mut i = 0;
            for o in self.asn1.iter() {
                f.write_str(&format!("{:02x}", o))?;
                i += 1;
                if i != self.asn1.len() {
                    f.write_str(" ")?;
                }
            }
            Ok(())
        }
    }
}

impl<'a> fmt::Debug for Oid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("OID(")?;
        <Oid as fmt::Display>::fmt(self, f)?;
        f.write_str(")")
    }
}

impl<'a> FromStr for Oid<'a> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: Result<Vec<_>, _> = s.split('.').map(|c| c.parse::<u64>()).collect();
        v.map_err(|_| ParseError::ParseIntError).and_then(|v| Oid::from(&v))
    }
}

#[cfg(test)]
mod tests {
    use crate::oid::Oid;
    use std::str::FromStr;

    #[cfg(feature = "bigint")]
    #[test]
    fn test_oid_fmt() {
        let oid = Oid::from(&[1, 2, 840, 113_549, 1, 1, 5]).unwrap();
        assert_eq!(format!("{}", oid), "1.2.840.113549.1.1.5".to_owned());
        assert_eq!(format!("{:?}", oid), "OID(1.2.840.113549.1.1.5)".to_owned());

        let oid = Oid::from_relative(&[840, 113_549, 1, 1, 5]).unwrap();
        let byte_ref = [0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 5];
        assert_eq!(byte_ref.as_ref(), oid.asn1.as_ref());
        assert_eq!(format!("{}", oid), "rel. 840.113549.1.1.5".to_owned());
        assert_eq!(format!("{:?}", oid), "OID(rel. 840.113549.1.1.5)".to_owned());
    }

    #[test]
    fn test_oid_from_str() {
        let oid_ref = Oid::from(&[1, 2, 840, 113_549, 1, 1, 5]).unwrap();
        let byte_ref = [42, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 5];
        let oid = Oid::from_str("1.2.840.113549.1.1.5").unwrap();
        assert_eq!(byte_ref.as_ref(), oid.asn1.as_ref());
        assert_eq!(oid_ref, oid);
    }

    #[test]
    fn test_zero_oid() {
        #[cfg(feature = "bigint")]
        {
            use num_traits::FromPrimitive;
            use num_bigint::BigUint;

            let oid_raw = Oid::new(std::borrow::Cow::Borrowed(&[0]));
            let ids: Vec<BigUint> = oid_raw.iter().collect(); 
            assert_eq!(vec![BigUint::from_u8(0).unwrap()], ids);
        }
        let oid_from = Oid::from(&[0]).unwrap();
        assert_eq!(oid_from.asn1.as_ref(), &[0]);
    }
}
