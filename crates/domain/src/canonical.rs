//! Canonical hashing: every hashed structure is encoded as an `ScVal` and hashed as XDR.
//!
//! # Why XDR rather than JSON
//!
//! These hashes are the project's evidence: they are what lets someone other than us confirm that
//! a given wasm was produced from the specification a user reviewed. That only works if both
//! sides can reproduce the same bytes, so the encoding has to be specified somewhere other than
//! in our source.
//!
//! XDR is that specification, and it is the format the rest of the ecosystem already speaks:
//! every Stellar SDK ships a codec generated from one schema, so implementations agree by
//! construction rather than by agreement. The architecture asks for "a specified canonical
//! encoding" and already prescribes canonical XDR for the authorization fingerprint
//! (`docs/architecture.md:259-262`); this brings the remaining preimages to the same footing.
//!
//! # The preimage
//!
//! ```text
//! preimage = ScVal::Vec [ ScVal::U32(canonicalization version)
//!                       , ScVal::String(domain)
//!                       , <encoded value>
//!                       ]
//! hash     = SHA-256(preimage encoded as XDR)
//! ```
//!
//! The domain travels **inside** the preimage, which is how the protocol does it: `HashIdPreimage`
//! is a union whose discriminant identifies the structure, and the hash is taken over the whole
//! encoded union. We deliberately do **not** reuse that union or any `EnvelopeType` discriminant.
//! Those numbers are a registry the protocol owns: taking one would mean a future protocol
//! addition silently collides with our hashes, and it would assert to any tool reading the bytes
//! that our specification is a protocol object, which is false. The pattern is what transfers —
//! a versioned, tagged structure hashed as XDR — with our own tag space.
//!
//! The tag is the domain constant itself (`ozpb:v1:policy-spec` and friends), carried as
//! `ScVal::String` rather than `ScVal::Symbol` because those constants contain `:` and `-`, which
//! `Symbol` does not admit. Reusing them avoids a second parallel list of tags: this crate has
//! already needed a test to stop one hand-maintained list of domains falling behind the
//! constants, and a second list would need the same. Note the `v1` inside a domain constant is
//! the *schema* version of that structure and is not the canonicalization version, which is the
//! separate `U32` above — the architecture treats those as distinct and so does this.
//!
//! # The encoding rules
//!
//! Written out because an external implementation has to follow them, and because "canonical"
//! is a claim that has to be checkable rather than asserted. The mapping is from serde's data
//! model, so the JSON wire form and this preimage are two encodings of one schema: a reader
//! holding our JSON can derive the `ScVal` from these rules alone.
//!
//! | Rust / serde | `ScVal` |
//! |---|---|
//! | `bool` | `Bool` |
//! | `i8` `i16` `i32` | `I32` |
//! | `i64` | `I64` |
//! | `i128` | `I128` |
//! | `u8` `u16` `u32` | `U32` |
//! | `u64` | `U64` |
//! | `u128` | `U128` |
//! | `f32` `f64` | **rejected** |
//! | `char`, `&str`, `String` | `String` |
//! | `&[u8]` | `Bytes` |
//! | `None` | `Vec []` |
//! | `Some(v)` | `Vec [v]` |
//! | `()`, unit struct | `Void` |
//! | newtype struct | the inner value, transparently |
//! | sequence, tuple, tuple struct | `Vec` |
//! | named struct | `Map`, keys `Symbol(field name)` |
//! | map | `Map`, keys the **encoded key** |
//! | unit variant | `Vec [Symbol(variant)]` |
//! | newtype variant | `Vec [Symbol(variant), inner]` |
//! | tuple variant | `Vec [Symbol(variant), fields…]` |
//! | struct variant | `Vec [Symbol(variant), Map]` |
//!
//! Four of those need their reasoning stated, because a different choice would have been
//! defensible and the difference is invisible until it bites.
//!
//! **Struct field names are `Symbol`s; map keys are not.** A field name is part of the schema and
//! fits `Symbol`'s charset and 32-byte limit — and holding it to that limit is useful, since it
//! fails loudly on a name no `ScVal` could carry. A map *key* is data: this project's maps are
//! keyed by 64-character hex hashes, 56-character strkeys, and template families like
//! `policy-templates/scope@1`, none of which are legal `Symbol`s. Keys are therefore encoded by
//! the same rules as any other value, which makes them `String`s here.
//!
//! **`Option` is wrapped rather than flattened.** Soroban's own convention maps `None` to `Void`
//! and `Some(v)` to `v`, which is compact but makes `None` and `Some(())` the same bytes. Wrapping
//! in a `Vec` costs a few bytes and makes the ambiguity unrepresentable, which is the trade this
//! project makes everywhere else.
//!
//! **Floats are rejected at encode time.** `clippy.toml` already bans them, but a lint is a
//! policy and this is a property: no float can reach a hash even through a type this crate has
//! never seen. `ScVal` has no float variant either, so the rejection matches the platform.
//!
//! **Map ordering is not ours to define.** `ScMap::sorted_from_entries` sorts by key and then
//! validates, and `impl Validate for ScMap` requires strictly ascending keys, which also rejects
//! duplicates. Writing our own comparison would be reimplementing a rule the ecosystem already
//! publishes — and getting it subtly different is exactly how two implementations stop agreeing.

use crate::{DomainError, CANONICALIZATION_VERSION};
use serde::{ser, Serialize};
use stellar_xdr::{
    Error as XdrError, Int128Parts, Limits, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, StringM,
    UInt128Parts, Validate, WriteXdr,
};

/// Byte ceiling for any canonical preimage this toolkit hashes. Published so schema crates can
/// treat it as a validated global budget — their per-field limits bound single items, and this
/// bounds what the items may compose into (exceeding it is [`DomainError::PreimageTooLarge`],
/// a limit, not a serialization accident).
pub const MAX_CANONICAL_PREIMAGE_BYTES: usize = 4 * 1024 * 1024;

/// XDR read/write limits for preimage encoding.
///
/// Depth is the default; length is [`MAX_CANONICAL_PREIMAGE_BYTES`] — bounded well above any
/// preimage this toolkit builds but far below the default 32 MiB, so a structure that grows
/// pathologically fails here rather than producing a hash over megabytes nobody will read.
fn preimage_limits() -> Limits {
    Limits {
        depth: 100,
        len: MAX_CANONICAL_PREIMAGE_BYTES,
    }
}

/// The canonical preimage bytes for `value` under `domain`: the versioned, tagged `ScVal`
/// encoded as XDR.
///
/// Exposed separately from [`canonical_hash`] so a test can assert the bytes themselves. A hash
/// test can only say two values differ; a byte test is what an external implementation can be
/// held to.
pub fn canonical_preimage_bytes<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Vec<u8>, DomainError> {
    canonical_preimage_bytes_of(domain, to_scval(value)?)
}

/// As [`canonical_preimage_bytes`], for a value already expressed as an `ScVal`.
///
/// Two hashed structures are built as `ScVal` directly rather than derived from a Rust type: the
/// authorization fingerprint, whose inputs are protocol XDR to begin with, and the signer set,
/// which hashes the `Signer` representation the account matches against. Routing those through
/// the serde encoder would encode `ScVal`'s *own* serde form and then map that to an `ScVal`
/// again — a double encoding, and one whose bytes nobody could derive from the rules.
pub fn canonical_preimage_bytes_of(domain: &str, value: ScVal) -> Result<Vec<u8>, DomainError> {
    let preimage = ScVal::Vec(Some(
        vec![
            ScVal::U32(CANONICALIZATION_VERSION),
            scstring(domain)?,
            value,
        ]
        .try_into()
        .map_err(|_| DomainError::Serialization("preimage vector rejected".to_string()))?,
    ));
    // Ask the crate whether the assembled value is a valid `ScVal` rather than assuming it. The
    // checks at each construction site cover what this module builds today; this covers what it
    // might build after a later edit, and costs one traversal of a structure about to be hashed.
    Validate::validate(&preimage).map_err(|e| {
        DomainError::Serialization(format!("the assembled preimage is not a valid ScVal: {e}"))
    })?;
    preimage.to_xdr(preimage_limits()).map_err(|e| match e {
        // The bounded writer aborting on length is the global size budget refusing the
        // value, not an encoding defect; give callers a variant they can translate into
        // their own limit errors.
        XdrError::LengthLimitExceeded => {
            DomainError::PreimageTooLarge(MAX_CANONICAL_PREIMAGE_BYTES)
        }
        other => DomainError::Serialization(format!("encoding the preimage as XDR: {other}")),
    })
}

/// Domain-separated canonical hash: SHA-256 over [`canonical_preimage_bytes`].
pub fn canonical_hash<T: Serialize>(domain: &str, value: &T) -> Result<crate::Hash32, DomainError> {
    Ok(crate::sha256(&canonical_preimage_bytes(domain, value)?))
}

/// As [`canonical_hash`], for a value already expressed as an `ScVal`.
pub fn canonical_hash_of(domain: &str, value: ScVal) -> Result<crate::Hash32, DomainError> {
    Ok(crate::sha256(&canonical_preimage_bytes_of(domain, value)?))
}

/// Encode any `Serialize` value as an `ScVal` under the rules in this module's documentation.
pub fn to_scval<T: Serialize>(value: &T) -> Result<ScVal, DomainError> {
    value.serialize(ScValSerializer)
}

fn symbol(name: &str) -> Result<ScVal, DomainError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| matches!(b as char, '_' | '0'..='9' | 'A'..='Z' | 'a'..='z'))
    {
        return Err(DomainError::Serialization(format!(
            "{name:?} cannot be a Symbol: a name in a hashed structure must be non-empty and use \
             only [a-zA-Z0-9_]"
        )));
    }
    let sym: ScSymbol = name.try_into().map_err(|_| {
        DomainError::Serialization(format!(
            "{name:?} cannot be a Symbol: a name in a hashed structure is limited to 32 bytes"
        ))
    })?;
    Ok(ScVal::Symbol(sym))
}

fn scstring(value: &str) -> Result<ScVal, DomainError> {
    let inner: StringM = value.try_into().map_err(|_| {
        DomainError::Serialization("string exceeds the XDR length limit".to_string())
    })?;
    Ok(ScVal::String(ScString(inner)))
}

fn vector(items: Vec<ScVal>) -> Result<ScVal, DomainError> {
    Ok(ScVal::Vec(Some(items.try_into().map_err(|_| {
        DomainError::Serialization("sequence exceeds the XDR length limit".to_string())
    })?)))
}

fn map(pairs: Vec<(ScVal, ScVal)>) -> Result<ScVal, DomainError> {
    let m = ScMap::sorted_from_entries(pairs.into_iter().map(|(key, val)| ScMapEntry { key, val }))
        .map_err(|e| DomainError::Serialization(format!("building a canonical map: {e}")))?;
    Ok(ScVal::Map(Some(m)))
}

fn reject_float(kind: &str) -> DomainError {
    DomainError::Serialization(format!(
        "{kind} cannot appear in a hashed structure: no float has a faithful canonical form, and \
         Stellar's own value system has no float variant"
    ))
}

// ---------------------------------------------------------------------------------------
// The serializer
// ---------------------------------------------------------------------------------------

struct ScValSerializer;

impl ser::Error for DomainError {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        DomainError::Serialization(msg.to_string())
    }
}

impl ser::Serializer for ScValSerializer {
    type Ok = ScVal;
    type Error = DomainError;

    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = SeqBuilder;
    type SerializeMap = MapBuilder;
    type SerializeStruct = StructBuilder;
    type SerializeStructVariant = StructBuilder;

    /// The preimage is typed binary, not text: a field that writes JSON as a decimal string
    /// (`crate::wide_int`) still encodes here as the integer its schema declares.
    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<ScVal, DomainError> {
        Ok(ScVal::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<ScVal, DomainError> {
        Ok(ScVal::I32(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<ScVal, DomainError> {
        Ok(ScVal::I32(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<ScVal, DomainError> {
        Ok(ScVal::I32(v))
    }
    fn serialize_i64(self, v: i64) -> Result<ScVal, DomainError> {
        Ok(ScVal::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<ScVal, DomainError> {
        Ok(ScVal::I128(Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        }))
    }
    fn serialize_u8(self, v: u8) -> Result<ScVal, DomainError> {
        Ok(ScVal::U32(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<ScVal, DomainError> {
        Ok(ScVal::U32(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<ScVal, DomainError> {
        Ok(ScVal::U32(v))
    }
    fn serialize_u64(self, v: u64) -> Result<ScVal, DomainError> {
        Ok(ScVal::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<ScVal, DomainError> {
        Ok(ScVal::U128(UInt128Parts {
            hi: (v >> 64) as u64,
            lo: v as u64,
        }))
    }
    // The workspace bans these types, and these two signatures are the exception the ban's own
    // comment anticipates: `serde::Serializer` requires them, and their entire body is the
    // refusal. Naming the type here is what lets the encoder turn the lint — a policy about code
    // we write — into a property that holds for any type this crate has never seen.
    #[allow(clippy::disallowed_types)]
    fn serialize_f32(self, _: f32) -> Result<ScVal, DomainError> {
        Err(reject_float("f32"))
    }
    #[allow(clippy::disallowed_types)]
    fn serialize_f64(self, _: f64) -> Result<ScVal, DomainError> {
        Err(reject_float("f64"))
    }
    fn serialize_char(self, v: char) -> Result<ScVal, DomainError> {
        scstring(&v.to_string())
    }
    fn serialize_str(self, v: &str) -> Result<ScVal, DomainError> {
        scstring(v)
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<ScVal, DomainError> {
        Ok(ScVal::Bytes(v.to_vec().try_into().map_err(|_| {
            DomainError::Serialization("byte string exceeds the XDR length limit".to_string())
        })?))
    }

    /// `None` is an empty vector and `Some` a one-element vector, so the two can never encode
    /// to the same bytes — see the module documentation.
    fn serialize_none(self) -> Result<ScVal, DomainError> {
        vector(Vec::new())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<ScVal, DomainError> {
        vector(vec![to_scval(&v)?])
    }

    fn serialize_unit(self) -> Result<ScVal, DomainError> {
        Ok(ScVal::Void)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<ScVal, DomainError> {
        Ok(ScVal::Void)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<ScVal, DomainError> {
        vector(vec![symbol(variant)?])
    }

    /// Transparent: a newtype struct is a name around one value and carries no schema of its own.
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<ScVal, DomainError> {
        to_scval(&v)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        v: &T,
    ) -> Result<ScVal, DomainError> {
        vector(vec![symbol(variant)?, to_scval(&v)?])
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<SeqBuilder, DomainError> {
        Ok(SeqBuilder {
            items: Vec::new(),
            tag: None,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder, DomainError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<SeqBuilder, DomainError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<SeqBuilder, DomainError> {
        Ok(SeqBuilder {
            items: Vec::new(),
            tag: Some(variant),
        })
    }

    fn serialize_map(self, _: Option<usize>) -> Result<MapBuilder, DomainError> {
        Ok(MapBuilder {
            pairs: Vec::new(),
            pending_key: None,
        })
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<StructBuilder, DomainError> {
        Ok(StructBuilder {
            fields: Vec::new(),
            tag: None,
        })
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<StructBuilder, DomainError> {
        Ok(StructBuilder {
            fields: Vec::new(),
            tag: Some(variant),
        })
    }
}

/// Sequences, tuples and tuple variants. `tag` is set only for a variant, whose name leads the
/// vector.
struct SeqBuilder {
    items: Vec<ScVal>,
    tag: Option<&'static str>,
}

impl SeqBuilder {
    fn push<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DomainError> {
        self.items.push(to_scval(&v)?);
        Ok(())
    }
    fn finish(self) -> Result<ScVal, DomainError> {
        match self.tag {
            None => vector(self.items),
            Some(tag) => {
                let mut items = vec![symbol(tag)?];
                items.extend(self.items);
                vector(items)
            }
        }
    }
}

impl ser::SerializeSeq for SeqBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DomainError> {
        self.push(v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

impl ser::SerializeTuple for SeqBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DomainError> {
        self.push(v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

impl ser::SerializeTupleStruct for SeqBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DomainError> {
        self.push(v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

impl ser::SerializeTupleVariant for SeqBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), DomainError> {
        self.push(v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

/// Maps. Keys are encoded by the ordinary rules — they are data, not schema — and ordering is
/// delegated to `ScMap::sorted_from_entries`.
///
/// Serde's map contract — key, then value, alternating, every key consumed — is upheld by every
/// derived implementation, but [`to_scval`] is generic over any `Serialize`, so a hand-written
/// implementation can break it. Each violation is refused rather than normalized: silently
/// dropping an orphaned key would let two different event streams collapse into the same
/// logical map, and this serializer exists to make bytes an argument, not a coincidence.
struct MapBuilder {
    pairs: Vec<(ScVal, ScVal)>,
    pending_key: Option<ScVal>,
}

impl ser::SerializeMap for MapBuilder {
    type Ok = ScVal;
    type Error = DomainError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), DomainError> {
        if self.pending_key.is_some() {
            return Err(DomainError::Serialization(
                "map key serialized while the previous key still has no value".to_string(),
            ));
        }
        self.pending_key = Some(to_scval(&key)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), DomainError> {
        let key = self.pending_key.take().ok_or_else(|| {
            DomainError::Serialization("map value serialized before its key".to_string())
        })?;
        self.pairs.push((key, to_scval(&value)?));
        Ok(())
    }

    fn end(self) -> Result<ScVal, DomainError> {
        if self.pending_key.is_some() {
            return Err(DomainError::Serialization(
                "map ended while its last key still has no value".to_string(),
            ));
        }
        map(self.pairs)
    }
}

/// Named structs and struct variants. Field names become `Symbol`s, which bounds them to 32
/// bytes of `[a-zA-Z0-9_]` — a name outside that fails here rather than silently encoding as
/// something else.
struct StructBuilder {
    fields: Vec<(ScVal, ScVal)>,
    tag: Option<&'static str>,
}

impl StructBuilder {
    fn push<T: ?Sized + Serialize>(
        &mut self,
        name: &'static str,
        v: &T,
    ) -> Result<(), DomainError> {
        self.fields.push((symbol(name)?, to_scval(&v)?));
        Ok(())
    }
    fn finish(self) -> Result<ScVal, DomainError> {
        let body = map(self.fields)?;
        match self.tag {
            None => Ok(body),
            Some(tag) => vector(vec![symbol(tag)?, body]),
        }
    }
}

impl ser::SerializeStruct for StructBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        name: &'static str,
        v: &T,
    ) -> Result<(), DomainError> {
        self.push(name, v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

impl ser::SerializeStructVariant for StructBuilder {
    type Ok = ScVal;
    type Error = DomainError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        name: &'static str,
        v: &T,
    ) -> Result<(), DomainError> {
        self.push(name, v)
    }
    fn end(self) -> Result<ScVal, DomainError> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains;
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct Named {
        beta: u32,
        alpha: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Shape {
        Unit,
        Newtype(u32),
        Tuple(u32, bool),
        Struct { field: u32 },
    }

    fn expect(value: &impl Serialize) -> ScVal {
        to_scval(value).expect("the fixture must encode")
    }

    #[test]
    fn a_named_struct_becomes_a_map_keyed_by_symbols() {
        let got = expect(&Named {
            beta: 7,
            alpha: "a".to_string(),
        });
        let ScVal::Map(Some(m)) = got else {
            panic!("a named struct must encode as a map, got {got:?}")
        };
        let keys: Vec<_> = m.0.iter().map(|e| e.key.clone()).collect();
        assert_eq!(
            keys,
            vec![symbol("alpha").unwrap(), symbol("beta").unwrap()],
            "field names must be Symbols, sorted by the crate's own comparison"
        );
    }

    #[test]
    fn map_keys_are_data_and_stay_strings() {
        // A registry snapshot is keyed by 64-character hex; a template map by a family name
        // holding `/` and `@`. Neither is a legal Symbol, so a rule that made map keys Symbols
        // would be unable to encode this project's own structures.
        let mut m = BTreeMap::new();
        m.insert("policy-templates/scope@1".to_string(), 1u32);
        m.insert("a".repeat(64), 2u32);
        let got = expect(&m);
        let ScVal::Map(Some(entries)) = got else {
            panic!("a map must encode as a map")
        };
        for entry in entries.0.iter() {
            assert!(
                matches!(entry.key, ScVal::String(_)),
                "map keys must encode as strings, got {:?}",
                entry.key
            );
        }
    }

    #[test]
    fn none_and_some_of_unit_are_distinguishable() {
        // Soroban's own Option convention maps None to Void and Some(v) to v, which collapses
        // these two. Wrapping keeps them apart by construction.
        let none: Option<()> = None;
        let some: Option<()> = Some(());
        assert_ne!(
            expect(&none),
            expect(&some),
            "None and Some(()) must not encode identically"
        );
    }

    #[test]
    fn enum_variants_carry_their_name_first() {
        assert_eq!(
            expect(&Shape::Unit),
            vector(vec![symbol("unit").unwrap()]).unwrap()
        );
        assert_eq!(
            expect(&Shape::Newtype(1)),
            vector(vec![symbol("newtype").unwrap(), ScVal::U32(1)]).unwrap()
        );
        assert_eq!(
            expect(&Shape::Tuple(1, true)),
            vector(vec![
                symbol("tuple").unwrap(),
                ScVal::U32(1),
                ScVal::Bool(true)
            ])
            .unwrap()
        );
        let ScVal::Vec(Some(items)) = expect(&Shape::Struct { field: 1 }) else {
            panic!("a struct variant must encode as a vector")
        };
        assert_eq!(items[0], symbol("struct").unwrap());
        assert!(matches!(items[1], ScVal::Map(Some(_))));
    }

    #[test]
    fn a_float_is_refused_rather_than_encoded() {
        let err = to_scval(&1.5f64).expect_err("a float must not encode");
        assert!(
            format!("{err}").contains("float"),
            "the refusal must say why: {err}"
        );
    }

    #[test]
    fn a_field_name_no_scval_could_carry_fails_loudly() {
        #[derive(Serialize)]
        struct Bad {
            #[serde(rename = "$schema")]
            schema: u32,
        }
        let err = to_scval(&Bad { schema: 1 }).expect_err("`$schema` is not a legal Symbol");
        assert!(
            format!("{err}").contains("Symbol"),
            "the refusal must name the constraint: {err}"
        );
    }

    /// Serde's map contract is strictly key-then-value, but `canonical_hash` is generic over
    /// any `Serialize`, so a hand-written implementation can violate it. The builder must
    /// refuse such a stream: normalizing it instead would let two different event streams
    /// collapse into the same logical map — and therefore into the same hash.
    #[test]
    fn a_key_replacing_an_unconsumed_key_is_refused_not_normalized() {
        struct DoubleKey;
        impl Serialize for DoubleKey {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_key("overwritten")?;
                m.serialize_key("kept")?;
                m.serialize_value(&1u32)?;
                m.end()
            }
        }
        let err = to_scval(&DoubleKey)
            .expect_err("a stream that would silently drop a key must not encode");
        assert!(
            format!("{err}").contains("previous key still has no value"),
            "the refusal must name this violation, not just some map error: {err}"
        );
    }

    /// The dual of the test above: a map that ends while its last key is still waiting for a
    /// value must fail rather than encode as if the key had never been serialized.
    #[test]
    fn a_map_ending_on_a_dangling_key_is_refused_not_normalized() {
        struct DanglingKey;
        impl Serialize for DanglingKey {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_key("dangling")?;
                m.end()
            }
        }
        let err = to_scval(&DanglingKey)
            .expect_err("a stream that would silently drop a key must not encode");
        assert!(
            format!("{err}").contains("ended while its last key still has no value"),
            "the refusal must name this violation, not just some map error: {err}"
        );
    }

    /// The bytes an external implementation has to reproduce.
    ///
    /// Two assertions, and the order matters. The first builds the expected `ScVal` **by hand
    /// from the documented rules** and compares the encoder against it: that is what makes this
    /// test evidence rather than a restatement, since a comparison against whatever the encoder
    /// emitted would pass for any encoder. The second pins the XDR bytes of that hand-built
    /// value, so the written specification and the code cannot drift apart in silence.
    #[test]
    fn the_preimage_is_the_structure_the_rules_describe() {
        let fixture = Named {
            beta: 7,
            alpha: "a".to_string(),
        };

        // Assembled from the rules table: a named struct is a map keyed by Symbols, the preimage
        // is [version, domain, value], and ordering comes from the crate's own comparison.
        let body = ScVal::Map(Some(
            ScMap::sorted_from_entries(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol("alpha".try_into().unwrap()),
                        val: ScVal::String(ScString("a".try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol("beta".try_into().unwrap()),
                        val: ScVal::U32(7),
                    },
                ]
                .into_iter(),
            )
            .unwrap(),
        ));
        let expected = ScVal::Vec(Some(
            vec![
                ScVal::U32(CANONICALIZATION_VERSION),
                ScVal::String(ScString(domains::POLICY_SPEC.try_into().unwrap())),
                body,
            ]
            .try_into()
            .unwrap(),
        ));

        let bytes = canonical_preimage_bytes(domains::POLICY_SPEC, &fixture)
            .expect("the fixture must encode");
        assert_eq!(
            bytes,
            expected.to_xdr(preimage_limits()).unwrap(),
            "the encoder disagrees with the structure the documented rules describe"
        );
        assert_eq!(
            hex::encode(&bytes),
            "00000010000000010000000300000003000000020000000e000000136f7a7062\
             3a76313a706f6c6963792d73706563000000001100000001000000020000000f\
             00000005616c7068610000000000000e00000001610000000000000f00000004\
             626574610000000300000007",
            "the preimage encoding changed; if that was intended, update \
             docs/CANONICAL-HASHING.md, this vector and CANONICALIZATION_VERSION together"
        );
    }
}
