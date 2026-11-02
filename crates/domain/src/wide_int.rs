//! Integers wider than a JSON number carries exactly.
//!
//! A JavaScript client — Claude Code is one — parses every JSON number as an f64, exact only up to
//! 2^53. An authorization nonce is a random `i64`, so nearly every real one arrives rounded, and a
//! recording passed back through such a client no longer matches its own raw XDR. Every amount in
//! the policy-spec schema is a decimal string for the same reason; this module gives a typed
//! integer field the same wire form without changing its type.
//!
//! Use it as `#[serde(with = "ozpb_domain::wide_int")]`, or for an `Option` as
//! `#[serde(default, with = "ozpb_domain::wide_int::option")]`: `with` turns off serde's implicit
//! "a missing field is `None`", so without `default` the field becomes required. A human-readable serializer — JSON — receives the canonical decimal string. The
//! canonical encoder is not human-readable and receives the integer itself, so the preimage keeps
//! `I64`/`U64`/`I128` and no typed structure's hash changes. Input accepts either form: a JSON
//! integer, as every document written before this module carries — within the 64-bit range, since
//! serde_json reads a wider literal as a float, which is refused — or a canonical decimal string:
//! optional `-`, no `+`, no leading zeros, no `-0`, in range, so one value has one spelling.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

/// The integer types this wire form applies to.
pub trait WideInt: Copy + fmt::Display + FromStr + Sized {
    #[doc(hidden)]
    const NAME: &'static str;
    #[doc(hidden)]
    fn from_i128(value: i128) -> Option<Self>;
    #[doc(hidden)]
    fn from_u128(value: u128) -> Option<Self>;
    #[doc(hidden)]
    fn serialize_native<S: Serializer>(self, serializer: S) -> Result<S::Ok, S::Error>;
}

macro_rules! wide_int {
    ($ty:ty, $serialize:ident) => {
        impl WideInt for $ty {
            const NAME: &'static str = stringify!($ty);
            fn from_i128(value: i128) -> Option<Self> {
                <$ty>::try_from(value).ok()
            }
            fn from_u128(value: u128) -> Option<Self> {
                <$ty>::try_from(value).ok()
            }
            fn serialize_native<S: Serializer>(self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.$serialize(self)
            }
        }
    };
}

wide_int!(i64, serialize_i64);
wide_int!(u64, serialize_u64);
wide_int!(i128, serialize_i128);

pub fn serialize<T: WideInt, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.collect_str(value)
    } else {
        value.serialize_native(serializer)
    }
}

pub fn deserialize<'de, T: WideInt, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
    deserializer.deserialize_any(WideIntVisitor(PhantomData))
}

/// The same wire form for an optional field; `None` stays `null`.
pub mod option {
    use super::WideInt;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: WideInt, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&Wire(*value)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T: WideInt, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error> {
        Ok(Option::<Wire<T>>::deserialize(deserializer)?.map(|Wire(value)| value))
    }

    struct Wire<T>(T);

    impl<T: WideInt> serde::Serialize for Wire<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            super::serialize(&self.0, serializer)
        }
    }

    impl<'de, T: WideInt> Deserialize<'de> for Wire<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            super::deserialize(deserializer).map(Wire)
        }
    }
}

struct WideIntVisitor<T>(PhantomData<T>);

impl<T: WideInt> WideIntVisitor<T> {
    fn in_range<E: de::Error>(value: Option<T>, shown: &dyn fmt::Display) -> Result<T, E> {
        value.ok_or_else(|| E::custom(format!("{shown} is out of range for {}", T::NAME)))
    }
}

impl<T: WideInt> Visitor<'_> for WideIntVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a {} as an integer or a canonical decimal string",
            T::NAME
        )
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<T, E> {
        Self::in_range(T::from_i128(value.into()), &value)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<T, E> {
        Self::in_range(T::from_u128(value.into()), &value)
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<T, E> {
        Self::in_range(T::from_i128(value), &value)
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<T, E> {
        Self::in_range(T::from_u128(value), &value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<T, E> {
        let parsed = value
            .parse::<T>()
            .ok()
            .filter(|parsed| parsed.to_string() == value);
        parsed.ok_or_else(|| {
            E::custom(format!(
                "{value:?} is not a canonical decimal {}: optional '-', no '+', no leading zeros, \
                 no \"-0\", in range",
                T::NAME
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wide {
        #[serde(with = "crate::wide_int")]
        signed: i64,
        #[serde(with = "crate::wide_int")]
        unsigned: u64,
        #[serde(with = "crate::wide_int")]
        amount: i128,
        #[serde(with = "crate::wide_int::option")]
        maybe: Option<i128>,
    }

    #[derive(Serialize)]
    struct Plain {
        signed: i64,
        unsigned: u64,
        amount: i128,
        maybe: Option<i128>,
    }

    fn sample() -> (Wide, Plain) {
        (
            Wide {
                signed: i64::MIN,
                unsigned: u64::MAX,
                amount: i128::MAX,
                maybe: Some(-1),
            },
            Plain {
                signed: i64::MIN,
                unsigned: u64::MAX,
                amount: i128::MAX,
                maybe: Some(-1),
            },
        )
    }

    #[test]
    fn json_carries_decimal_strings_and_reads_them_back() {
        let (wide, _) = sample();
        let json = serde_json::to_value(&wide).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "signed": i64::MIN.to_string(),
                "unsigned": u64::MAX.to_string(),
                "amount": i128::MAX.to_string(),
                "maybe": "-1",
            })
        );
        assert_eq!(serde_json::from_value::<Wide>(json).unwrap(), wide);
        let none = Wide {
            maybe: None,
            ..sample().0
        };
        let json = serde_json::to_string(&none).unwrap();
        assert!(json.contains("\"maybe\":null"), "{json}");
        assert_eq!(serde_json::from_str::<Wide>(&json).unwrap(), none);
    }

    /// Documents written before this module carry numbers; they still load, from text and from
    /// an already-parsed value.
    #[test]
    fn json_integers_are_still_accepted() {
        let text = r#"{"signed": -9223372036854775808, "unsigned": 18446744073709551615,
                       "amount": 5, "maybe": 7}"#;
        let expected = Wide {
            signed: i64::MIN,
            unsigned: u64::MAX,
            amount: 5,
            maybe: Some(7),
        };
        assert_eq!(serde_json::from_str::<Wide>(text).unwrap(), expected);
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::from_value::<Wide>(value).unwrap(), expected);
    }

    #[test]
    fn a_value_has_one_spelling() {
        for bad in ["+1", "01", "-0", " 1", "1 ", "", "1.0", "1e3", "0x10"] {
            let json = serde_json::json!({
                "signed": bad, "unsigned": "1", "amount": "1", "maybe": null
            });
            assert!(
                serde_json::from_value::<Wide>(json).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn out_of_range_values_are_refused_in_either_form() {
        for unsigned in [
            serde_json::json!(-1),
            serde_json::json!("-1"),
            serde_json::json!("18446744073709551616"),
        ] {
            let json = serde_json::json!({
                "signed": "1", "unsigned": unsigned, "amount": "1", "maybe": null
            });
            assert!(
                serde_json::from_value::<Wide>(json).is_err(),
                "{unsigned} must be refused"
            );
        }
        let float =
            serde_json::json!({"signed": 1.5, "unsigned": "1", "amount": "1", "maybe": null});
        assert!(serde_json::from_value::<Wide>(float).is_err());
    }

    /// The canonical preimage is the integer, exactly as for a plain field: adopting the wire form
    /// changes no hash.
    #[test]
    fn the_canonical_preimage_is_unchanged() {
        let (wide, plain) = sample();
        assert_eq!(
            crate::canonical_preimage_bytes(crate::domains::RECORDING, &wide).unwrap(),
            crate::canonical_preimage_bytes(crate::domains::RECORDING, &plain).unwrap()
        );
    }
}
