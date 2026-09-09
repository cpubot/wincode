//! Regression coverage for the derive's trusted windows across dynamic fields.
#![allow(clippy::arithmetic_side_effects)]

use {
    super::*,
    crate::{
        SchemaRead, SchemaReadContext, SchemaWrite, config::Config, deserialize, io, serialize,
    },
};

// Deliberately conservative metadata lets us observe the struct's windows without
// introducing nested windows from a container implementation.
#[derive(Debug, PartialEq)]
struct DynamicByte(u8);

unsafe impl<C: Config> SchemaWrite<C> for DynamicByte {
    type Src = Self;
    fn size_of(_: &Self) -> WriteResult<usize> {
        Ok(1)
    }
    fn write(mut writer: impl Writer, src: &Self) -> WriteResult<()> {
        writer.write(&[src.0])?;
        Ok(())
    }
}

unsafe impl<'de, C: Config> SchemaRead<'de, C> for DynamicByte {
    type Dst = Self;
    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        dst.write(Self(reader.take_byte()?));
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum Event {
    Window(usize),
    Finish,
    ParentWrite(usize),
    ParentFinish,
}

struct RecordingWriter {
    bytes: Vec<u8>,
    events: Vec<Event>,
}

struct Window<'a, W> {
    inner: W,
    events: &'a mut Vec<Event>,
}

impl<W: Writer> Writer for Window<'_, W> {
    fn write(&mut self, src: &[u8]) -> io::WriteResult<()> {
        self.inner.write(src)
    }
    fn finish(&mut self) -> io::WriteResult<()> {
        self.events.push(Event::Finish);
        self.inner.finish()
    }
}

impl Writer for RecordingWriter {
    fn write(&mut self, src: &[u8]) -> io::WriteResult<()> {
        self.events.push(Event::ParentWrite(src.len()));
        self.bytes.write(src)
    }
    unsafe fn as_trusted_for(&mut self, size: usize) -> io::WriteResult<impl Writer> {
        self.events.push(Event::Window(size));
        Ok(Window {
            // SAFETY: forwards the caller's exact window contract.
            inner: unsafe { self.bytes.as_trusted_for(size) }?,
            events: &mut self.events,
        })
    }
    fn finish(&mut self) -> io::WriteResult<()> {
        self.events.push(Event::ParentFinish);
        Ok(())
    }
}

struct RecordingReader<'a> {
    bytes: &'a [u8],
    windows: Vec<usize>,
}

// SAFETY: copying and trusted windows delegate to the slice reader.
unsafe impl<'de> Reader<'de> for RecordingReader<'de> {
    fn copy_into_slice(&mut self, dst: &mut [u8]) -> io::ReadResult<()> {
        self.bytes.copy_into_slice(dst)
    }
    unsafe fn as_trusted_for(&mut self, size: usize) -> io::ReadResult<impl Reader<'de>> {
        self.windows.push(size);
        unsafe { self.bytes.as_trusted_for(size) }
    }
}

#[test]
fn windows_cover_each_run_and_finish_before_parent_resumes() {
    #[derive(SchemaRead, SchemaWrite, Debug, PartialEq)]
    #[wincode(internal)]
    struct Runs {
        a: u16,
        #[wincode(skip)]
        skipped: String,
        b: u32,
        dynamic: DynamicByte,
        c: u16,
        zero: (),
        d: u32,
        other: DynamicByte,
        e: u64,
    }
    let value = Runs {
        a: 1,
        skipped: String::new(),
        b: 2,
        dynamic: DynamicByte(3),
        c: 4,
        zero: (),
        d: 5,
        other: DynamicByte(6),
        e: 7,
    };
    let mut writer = RecordingWriter {
        bytes: Vec::new(),
        events: Vec::new(),
    };
    crate::serialize_into(&mut writer, &value).unwrap();
    assert_eq!(
        writer.events,
        [
            Event::Window(6),
            Event::Finish,
            Event::ParentWrite(1),
            Event::Window(6),
            Event::Finish,
            Event::ParentWrite(1),
            Event::Window(8),
            Event::Finish,
            Event::ParentFinish,
        ]
    );
    let mut reader = RecordingReader {
        bytes: &writer.bytes,
        windows: Vec::new(),
    };
    assert_eq!(
        <Runs as SchemaRead<DefaultConfig>>::get(&mut reader).unwrap(),
        value
    );
    assert_eq!(reader.windows, [6, 6, 8]);
    assert!(reader.bytes.is_empty());
}

#[test]
fn runs_follow_generic_and_configuration_metadata() {
    #[derive(SchemaRead, SchemaWrite, Debug, PartialEq)]
    #[wincode(internal)]
    struct Generic<T, const N: usize> {
        a: u8,
        b: u8,
        middle: T,
        c: [u8; N],
        d: u16,
    }
    fn check<T: SchemaWrite<DefaultConfig, Src = T>>(value: &T, expected: &[Event]) {
        let mut writer = RecordingWriter {
            bytes: Vec::new(),
            events: Vec::new(),
        };
        crate::serialize_into(&mut writer, value).unwrap();
        assert_eq!(writer.events, expected);
    }
    check(
        &Generic {
            a: 1,
            b: 2,
            middle: 3u32,
            c: [4; 2],
            d: 5,
        },
        &[Event::Window(10), Event::Finish, Event::ParentFinish],
    );
    check(
        &Generic {
            a: 1,
            b: 2,
            middle: DynamicByte(3),
            c: [4; 2],
            d: 5,
        },
        &[
            Event::Window(2),
            Event::Finish,
            Event::ParentWrite(1),
            Event::Window(4),
            Event::Finish,
            Event::ParentFinish,
        ],
    );

    let value = Generic {
        a: 1,
        b: 2,
        middle: 1000u32,
        c: [4; 2],
        d: 500,
    };
    let config = config::Configuration::default().with_varint_encoding();
    let bytes = config::serialize(&value, config).unwrap();
    assert_eq!(
        config::deserialize::<Generic<u32, 2>, _>(&bytes, config).unwrap(),
        value
    );
    let mut reader = RecordingReader {
        bytes: &bytes,
        windows: Vec::new(),
    };
    assert_eq!(
        config::deserialize_from::<Generic<u32, 2>, _>(&mut reader, config).unwrap(),
        value
    );
    // u32/u16 become dynamic under varint; the u8 runs remain static.
    assert_eq!(reader.windows, [2, 2]);
}

#[test]
fn owned_context_is_consumed_once_in_static_or_dynamic_run() {
    struct Owned(String);
    #[derive(Debug, PartialEq)]
    struct ContextField<const STATIC: bool>(String);
    unsafe impl<'de, C: Config, const STATIC: bool> SchemaReadContext<'de, C, Owned>
        for ContextField<STATIC>
    {
        type Dst = Self;
        const TYPE_META: TypeMeta = if STATIC {
            TypeMeta::Static {
                size: 0,
                zero_copy: false,
            }
        } else {
            TypeMeta::Dynamic
        };
        fn read_with_context(
            ctx: Owned,
            _: impl Reader<'de>,
            dst: &mut MaybeUninit<Self>,
        ) -> ReadResult<()> {
            dst.write(Self(ctx.0));
            Ok(())
        }
    }
    #[derive(SchemaRead)]
    #[wincode(internal, context = "Owned")]
    struct Contextual<const STATIC: bool> {
        a: u8,
        dynamic: DynamicByte,
        #[wincode(context)]
        field: ContextField<STATIC>,
        b: u16,
    }
    fn check<const STATIC: bool>() {
        let value = <Contextual<STATIC> as SchemaReadContext<DefaultConfig, _>>::get_with_context(
            Owned("owned".into()),
            [1, 2, 3, 0].as_slice(),
        )
        .unwrap();
        assert_eq!(
            (value.a, value.dynamic, value.field.0, value.b),
            (1, DynamicByte(2), "owned".into(), 3)
        );
    }
    check::<true>();
    check::<false>();
}

#[test]
fn recursive_struct_with_static_runs() {
    #[derive(SchemaRead, SchemaWrite, Debug, PartialEq)]
    #[wincode(internal)]
    struct Node {
        a: u64,
        children: Vec<Node>,
        b: u32,
        c: u16,
    }
    let value = Node {
        a: 1,
        children: vec![Node {
            a: 2,
            children: vec![],
            b: 3,
            c: 4,
        }],
        b: 5,
        c: 6,
    };
    let bytes = serialize(&value).unwrap();
    assert_eq!(deserialize::<Node>(&bytes).unwrap(), value);
}

#[test]
fn skipped_and_zero_sized_only_runs_initialize() {
    #[derive(SchemaRead, SchemaWrite, Debug, PartialEq)]
    #[wincode(internal)]
    struct Empty(
        #[wincode(skip(default_val = String::from("default")))] String,
        (),
    );
    let value = Empty("default".into(), ());
    assert!(serialize(&value).unwrap().is_empty());
    assert_eq!(deserialize::<Empty>(&[]).unwrap(), value);
}

#[test]
fn later_runs_preserve_borrows_into_the_backing_buffer() {
    #[derive(SchemaRead, Debug, PartialEq)]
    #[wincode(internal)]
    struct Borrowed<'a> {
        head: Option<u8>,
        a: &'a u8,
        b: &'a u8,
        middle: Option<u8>,
        c: &'a u8,
        d: &'a u8,
    }
    let mut bytes = [1, 9, 2, 3, 1, 10, 6, 7];
    let value = <Borrowed<'_> as SchemaRead<DefaultConfig>>::get(bytes.as_mut_slice()).unwrap();
    assert_eq!((value.head, value.middle), (Some(9), Some(10)));
    assert_eq!((*value.a, *value.b, *value.c, *value.d), (2, 3, 6, 7));
    let pointers = [value.a as *const u8, value.b, value.c, value.d];
    assert_eq!(
        pointers,
        [2, 3, 6, 7].map(|i| core::ptr::from_ref(&bytes[i]))
    );
}

#[test]
fn later_write_failure_preserves_only_initialized_bytes() {
    struct Fails;
    unsafe impl<C: Config> SchemaWrite<C> for Fails {
        type Src = Self;
        const TYPE_META: TypeMeta = TypeMeta::Static {
            size: 2,
            zero_copy: false,
        };
        fn size_of(_: &Self) -> WriteResult<usize> {
            Ok(2)
        }
        fn write(mut writer: impl Writer, _: &Self) -> WriteResult<()> {
            writer.write(&[5])?;
            Err(crate::error::WriteError::Custom("partial field write"))
        }
    }
    #[derive(SchemaWrite)]
    #[wincode(internal)]
    struct Runs {
        a: u16,
        dynamic: DynamicByte,
        b: u16,
        fails: Fails,
        c: u16,
    }
    let value = Runs {
        a: 1,
        dynamic: DynamicByte(2),
        b: 3,
        fails: Fails,
        c: 4,
    };
    let mut writer = RecordingWriter {
        bytes: Vec::new(),
        events: Vec::new(),
    };
    assert!(crate::serialize_into(&mut writer, &value).is_err());
    assert_eq!(writer.bytes, [1, 0, 2, 3, 0, 5]);
    assert_eq!(
        writer.events,
        [
            Event::Window(2),
            Event::Finish,
            Event::ParentWrite(1),
            Event::Window(6)
        ]
    );
}

#[test]
fn failures_drop_initialized_declarations_across_runs() {
    use std::cell::RefCell;
    thread_local! {
        static EVENTS: RefCell<Vec<i8>> = const { RefCell::new(Vec::new()) };
    }
    struct Tracked<const ID: i8>;
    impl<const ID: i8> Default for Tracked<ID> {
        fn default() -> Self {
            EVENTS.with_borrow_mut(|events| events.push(ID));
            Self
        }
    }
    impl<const ID: i8> Drop for Tracked<ID> {
        fn drop(&mut self) {
            EVENTS.with_borrow_mut(|events| events.push(-ID));
        }
    }
    unsafe impl<'de, C: Config, const ID: i8> SchemaRead<'de, C> for Tracked<ID> {
        type Dst = Self;
        const TYPE_META: TypeMeta = TypeMeta::Static {
            size: 1,
            zero_copy: false,
        };
        fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
            reader.take_byte()?;
            // This custom default records initialization despite the type being a ZST.
            #[allow(clippy::default_constructed_unit_structs)]
            dst.write(Self::default());
            Ok(())
        }
    }
    #[derive(SchemaRead)]
    #[wincode(internal)]
    struct Runs {
        #[wincode(skip)]
        _before: Tracked<1>,
        _a: Tracked<2>,
        _valid: bool,
        #[wincode(skip)]
        _boundary: Tracked<3>,
        _dynamic: Option<Tracked<4>>,
        #[wincode(skip)]
        _after: Tracked<5>,
        _b: Tracked<6>,
        _valid2: bool,
        _tail: Option<Tracked<7>>,
        #[wincode(skip)]
        _trailing: Tracked<8>,
    }
    let bytes = [0, 1, 1, 0, 0, 1, 1, 0];
    let value = deserialize::<Runs>(&bytes).unwrap();
    assert_eq!(EVENTS.with_borrow(Clone::clone), [1, 2, 3, 4, 5, 6, 7, 8]);
    drop(value);
    EVENTS.with_borrow_mut(Vec::clear);

    let mut failures: Vec<Vec<u8>> = (0..bytes.len()).map(|len| bytes[..len].to_vec()).collect();
    // Fail both inside a static window and in each dynamic field.
    for index in [1, 2, 5, 6] {
        let mut invalid = bytes.to_vec();
        invalid[index] = 2;
        failures.push(invalid);
    }
    for invalid in failures {
        for buffered in [false, true] {
            let result = if buffered {
                <Runs as SchemaRead<DefaultConfig>>::get(io::std_read::ReadAdapter::new(
                    invalid.as_slice(),
                ))
            } else {
                deserialize::<Runs>(&invalid)
            };
            assert!(result.is_err());
            let events = EVENTS.with_borrow_mut(core::mem::take);
            let count = events.len() / 2;
            let initialized: Vec<i8> = (1..=count as i8).collect();
            assert_eq!(&events[..count], initialized);
            assert_eq!(
                &events[count..],
                initialized.iter().rev().map(|id| -id).collect::<Vec<_>>()
            );
        }
    }

    fn panic_default() -> Tracked<3> {
        panic!("skipped initializer failed")
    }
    #[derive(SchemaRead)]
    #[wincode(internal)]
    struct Panics {
        _a: Tracked<1>,
        _dynamic: Option<Tracked<2>>,
        #[wincode(skip(default_val = panic_default()))]
        _skipped: Tracked<3>,
        _b: u8,
    }
    let panic = std::panic::catch_unwind(|| deserialize::<Panics>(&[0, 1, 0, 0]));
    assert!(panic.is_err());
    assert_eq!(EVENTS.with_borrow_mut(core::mem::take), [1, 2, -2, -1]);
}
