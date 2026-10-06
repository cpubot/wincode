#![no_main]

use {
    agave_votor_messages::{
        consensus_message::Block,
        reward_certificate::{NotarRewardCertificate, SkipRewardCertificate},
        wire::{
            ExpectedShredVersion, VersionedWireConsensusMessage, VotePayloadToSign,
            WireBlockCertMessage, WireCertSignature, WireConsensusMessageV1,
        },
    },
    libfuzzer_sys::fuzz_target,
    solana_address::Address,
    solana_entry::{
        block_component::{
            BlockComponent, BlockFinalizationCert, BlockFooterV1, BlockHeaderV1, BlockMarkerV1,
            GenesisCertBlockMarker, UpdateParentV1, VersionedBlockFooter, VersionedBlockHeader,
            VersionedBlockMarker, VersionedUpdateParent, VotesAggregate,
        },
        entry::Entry,
    },
    solana_fee_calculator::FeeCalculator,
    solana_hash::Hash,
    solana_message::{
        compiled_instruction::CompiledInstruction,
        v0::{Message as V0Message, MessageAddressTableLookup},
        Message as LegacyMessage, MessageHeader, VersionedMessage,
    },
    solana_nonce::{
        state::{Data as NonceData, DurableNonce, State as NonceState},
        versions::Versions as NonceVersions,
    },
    solana_signature::Signature,
    solana_transaction::{versioned::VersionedTransaction, Transaction},
    wincode::{config::DefaultConfig, SchemaReadContext, SchemaWrite},
};

macro_rules! fuzz_roundtrip {
    ($data:expr, $ty:ty) => {
        if let Ok(value) = wincode::deserialize_exact::<$ty>($data) {
            let serialized = wincode::serialize(&value).expect("serialize should succeed");
            assert_eq!($data, serialized, "deserialize -> serialize != orignal_data for type {}\nserialized {:?}\noriginal   {:?}", stringify!($ty), serialized, $data,);
            let roundtrip: $ty =
                wincode::deserialize(&serialized).expect("roundtrip deserialize should succeed");
            assert_eq!(value, roundtrip, "roundtrip failed for {}", stringify!($ty));
        }
    };
}

fn fuzz_wire_roundtrip<T>(data: &[u8])
where
    T: for<'de> SchemaReadContext<'de, DefaultConfig, ExpectedShredVersion, Dst = T>
        + SchemaWrite<DefaultConfig, Src = T>
        + std::fmt::Debug
        + PartialEq,
{
    // Both wire formats end in the shred version. Use it as the expected value
    // so arbitrary valid messages can exercise successful deserialization.
    let Some(shred_version) = data.last_chunk::<2>() else {
        return;
    };
    let expected = ExpectedShredVersion(u16::from_le_bytes(*shred_version));
    let mut remaining = data;
    if let Ok(value) = T::get_with_context(expected, &mut remaining) {
        if !remaining.is_empty() {
            return;
        }
        let serialized = wincode::serialize(&value).expect("serialize should succeed");
        assert_eq!(data, serialized);
        let roundtrip: T = wincode::deserialize_with_context(expected, &serialized)
            .expect("roundtrip deserialize should succeed");
        assert_eq!(value, roundtrip);
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_roundtrip!(data, Address);
    fuzz_roundtrip!(data, Hash);
    fuzz_roundtrip!(data, DurableNonce);
    fuzz_roundtrip!(data, Signature);
    fuzz_roundtrip!(data, FeeCalculator);
    fuzz_roundtrip!(data, MessageHeader);
    fuzz_roundtrip!(data, CompiledInstruction);
    fuzz_roundtrip!(data, MessageAddressTableLookup);
    fuzz_roundtrip!(data, NonceData);
    fuzz_roundtrip!(data, NonceState);
    fuzz_roundtrip!(data, NonceVersions);
    fuzz_roundtrip!(data, LegacyMessage);
    fuzz_roundtrip!(data, V0Message);
    fuzz_roundtrip!(data, VersionedMessage);
    fuzz_roundtrip!(data, Transaction);
    fuzz_roundtrip!(data, VersionedTransaction);
    fuzz_roundtrip!(data, Entry);
    fuzz_roundtrip!(data, SkipRewardCertificate);
    fuzz_roundtrip!(data, NotarRewardCertificate);
    // Agave 4.3 serializes wire types rather than the internal vote/certificate types.
    fuzz_roundtrip!(data, Block);
    fuzz_roundtrip!(data, VotePayloadToSign);
    fuzz_roundtrip!(data, WireCertSignature);
    fuzz_roundtrip!(data, WireBlockCertMessage);
    fuzz_wire_roundtrip::<WireConsensusMessageV1>(data);
    fuzz_wire_roundtrip::<VersionedWireConsensusMessage>(data);
    fuzz_roundtrip!(data, BlockFooterV1);
    fuzz_roundtrip!(data, BlockHeaderV1);
    fuzz_roundtrip!(data, UpdateParentV1);
    fuzz_roundtrip!(data, GenesisCertBlockMarker);
    fuzz_roundtrip!(data, BlockFinalizationCert);
    fuzz_roundtrip!(data, VotesAggregate);
    fuzz_roundtrip!(data, VersionedBlockFooter);
    fuzz_roundtrip!(data, VersionedBlockHeader);
    fuzz_roundtrip!(data, VersionedUpdateParent);
    fuzz_roundtrip!(data, BlockMarkerV1);
    fuzz_roundtrip!(data, VersionedBlockMarker);
    fuzz_roundtrip!(data, BlockComponent);
});
