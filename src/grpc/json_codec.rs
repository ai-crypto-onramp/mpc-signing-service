//! A serde-JSON tonic codec.
//!
//! wallet-management serves gRPC with `grpc.ForceServerCodec(jsonCodec{})`
//! over plain Go structs (a documented deviation from protobuf stubs in that
//! repo). This codec lets our tonic client speak the same wire format.

use std::marker::PhantomData;

use bytes::{Buf, BufMut};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

pub struct JsonCodec<E, D> {
    _marker: PhantomData<(E, D)>,
}

impl<E, D> Default for JsonCodec<E, D> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

pub struct JsonEncoder<E>(PhantomData<E>);
pub struct JsonDecoder<D>(PhantomData<D>);

impl<E: Serialize> Encoder for JsonEncoder<E> {
    type Item = E;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        let bytes =
            serde_json::to_vec(&item).map_err(|e| Status::internal(format!("json encode: {e}")))?;
        dst.put_slice(&bytes);
        Ok(())
    }
}

impl<D: DeserializeOwned> Decoder for JsonDecoder<D> {
    type Item = D;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let bytes = src.copy_to_bytes(src.remaining());
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Status::internal(format!("json decode: {e}")))
    }
}

impl<E, D> Codec for JsonCodec<E, D>
where
    E: Serialize + Send + 'static,
    D: DeserializeOwned + Send + 'static,
{
    type Encode = E;
    type Decode = D;
    type Encoder = JsonEncoder<E>;
    type Decoder = JsonDecoder<D>;

    fn encoder(&mut self) -> Self::Encoder {
        JsonEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        JsonDecoder(PhantomData)
    }
}
