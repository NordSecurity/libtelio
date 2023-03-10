use std::io::{Error as IOError, Result as IOResult};
use std::sync::Arc;
use tokio::sync::Mutex;
use trust_dns_proto::{rr::Record, serialize::binary::BinEncoder};
use trust_dns_server::{
    authority::MessageResponse,
    server::{ResponseHandler, ResponseInfo},
};

#[derive(Clone)]
/// Resolver converts DNS responses to &[u8].
pub struct Resolver(pub(crate) Arc<Mutex<Vec<u8>>>);

impl Resolver {
    /// Create new `Resolver`.
    pub fn new() -> Self {
        Resolver(Arc::new(Mutex::new(Vec::new())))
    }
}

#[async_trait::async_trait]
impl ResponseHandler for Resolver {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> IOResult<ResponseInfo> {
        let mut buf = self.0.lock().await;
        buf.clear();
        // TODO: fix a bug in https://docs.rs/trust-dns-proto/0.20.3/src/trust_dns_proto/serialize/binary/encoder.rs.html#61
        // so that its possible to use BinEncoder::with_offset
        let mut encoder = BinEncoder::new(&mut buf);
        response
            .destructive_emit(&mut encoder)
            .map_err(Into::<IOError>::into)
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}
