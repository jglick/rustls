use crate::error::TlsError;
use crate::keylog::{KeyLog, NoKeyLog};
use crate::kx::{SupportedKxGroup, ALL_KX_GROUPS};
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::enums::CipherSuite;
use crate::msgs::enums::ProtocolVersion;
use crate::msgs::enums::SignatureScheme;
use crate::msgs::enums::{AlertDescription, HandshakeType};
use crate::msgs::handshake::CertificatePayload;
use crate::msgs::handshake::ClientExtension;
use crate::msgs::message::Message;
use crate::session::{MessageType, Session, SessionCommon};
use crate::sign;
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::{key, RootCertStore};

use std::fmt;
use std::io::{self, IoSlice};
use std::mem;
use std::sync::Arc;

#[macro_use]
mod hs;
mod common;
pub mod handy;
mod tls12;
mod tls13;

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
///
/// `put` is a mutating operation; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresClientSessions: Send + Sync {
    /// Stores a new `value` for `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Returns the latest value for `key`.  Returns `None`
    /// if there's no such value.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert: Send + Sync {
    /// With the server-supplied acceptable issuers in `acceptable_issuers`,
    /// the server's supported signature schemes in `sigschemes`,
    /// return a certificate chain and signing key to authenticate.
    ///
    /// `acceptable_issuers` is undecoded and unverified by the rustls
    /// library, but it should be expected to contain a DER encodings
    /// of X501 NAMEs.
    ///
    /// Return None to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<sign::CertifiedKey>;

    /// Return true if any certificates at all are available.
    fn has_certs(&self) -> bool;
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub ciphersuites: Vec<&'static SupportedCipherSuite>,

    /// List of supported key exchange algorithms, in preference order -- the
    /// first elemnt is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    pub kx_groups: Vec<&'static SupportedKxGroup>,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How we store session data or tickets.
    pub session_persistence: Arc<dyn StoresClientSessions>,

    /// Our MTU.  If None, we don't limit TLS message sizes.
    pub mtu: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Whether to support RFC5077 tickets.  You must provide a working
    /// `session_persistence` member for this to have any meaningful
    /// effect.
    ///
    /// The default is true.
    pub enable_tickets: bool,

    /// Supported versions, in no particular order.  The default
    /// is all supported versions.
    pub versions: Vec<ProtocolVersion>,

    /// Whether to send the Server Name Indication (SNI) extension
    /// during the client handshake.
    ///
    /// The default is true.
    pub enable_sni: bool,

    /// How to verify the server certificate chain.
    verifier: Arc<dyn verify::ServerCertVerifier>,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Whether to send data on the first flight ("early data") in
    /// TLS 1.3 handshakes.
    ///
    /// The default is false.
    pub enable_early_data: bool,
}

impl ClientConfig {
    /// Make a `ClientConfig`.
    ///
    /// The verifier will use the roots in `root_store` and CT logs (if any) in
    /// `ct_logs`.
    ///
    /// `ciphersuites` contains the list of cipher suites to enable. It should
    /// generally be `DEFAULT_CIPHERSUITES`.
    ///
    /// No ALPN protocols will be enabled, and client auth will be supported
    /// by default. The default session persistence provider stores up to 32
    /// items in memory.
    pub fn new(
        root_store: RootCertStore,
        ct_logs: &'static [&'static sct::Log],
        ciphersuites: &[&'static SupportedCipherSuite],
    ) -> Self {
        let verifier = verify::WebPkiVerifier::new(root_store, ct_logs);
        Self::new_(Arc::new(verifier), ciphersuites)
    }

    /// Make a `ClientConfig` with a custom certificate verifier.
    ///
    /// `verifier` is the certificate verifier to use.
    ///
    /// `ciphersuites` contains the list of cipher suites to enable. It should
    /// generally be `DEFAULT_CIPHERSUITES`.
    ///
    /// No ALPN protocols will be enabled, and client auth will be supported
    /// by default. The default session persistence provider stores up to 32
    /// items in memory.
    #[cfg(feature = "dangerous_configuration")]
    pub fn new_dangerous(
        verifier: Arc<dyn verify::ServerCertVerifier>,
        ciphersuites: &[&'static SupportedCipherSuite],
    ) -> Self {
        Self::new_(verifier, ciphersuites)
    }

    fn new_(
        verifier: Arc<dyn verify::ServerCertVerifier>,
        ciphersuites: &[&'static SupportedCipherSuite],
    ) -> Self {
        Self {
            ciphersuites: ciphersuites.to_vec(),
            kx_groups: ALL_KX_GROUPS.to_vec(),
            alpn_protocols: Vec::new(),
            session_persistence: handy::ClientSessionMemoryCache::new(32),
            mtu: None,
            client_auth_cert_resolver: Arc::new(handy::FailResolveClientCert {}),
            enable_tickets: true,
            versions: vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
            enable_sni: true,
            verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_early_data: false,
        }
    }

    #[doc(hidden)]
    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(&v)
            && self
                .ciphersuites
                .iter()
                .any(|cs| cs.usable_for_version(v))
    }

    #[doc(hidden)]
    pub fn get_verifier(&self) -> &dyn verify::ServerCertVerifier {
        self.verifier.as_ref()
    }

    /// Set the ALPN protocol list to the given protocol names.
    /// Overwrites any existing configured protocols.
    /// The first element in the `protocols` list is the most
    /// preferred, the last is the least preferred.
    pub fn set_protocols(&mut self, protocols: &[Vec<u8>]) {
        self.alpn_protocols.clear();
        self.alpn_protocols
            .extend_from_slice(protocols);
    }

    /// Sets persistence layer to `persist`.
    pub fn set_persistence(&mut self, persist: Arc<dyn StoresClientSessions>) {
        self.session_persistence = persist;
    }

    /// Sets MTU to `mtu`.  If None, the default is used.
    /// If Some(x) then x must be greater than 5 bytes.
    pub fn set_mtu(&mut self, mtu: &Option<usize>) {
        // Internally our MTU relates to fragment size, and does
        // not include the TLS header overhead.
        //
        // Externally the MTU is the whole packet size.  The difference
        // is PACKET_OVERHEAD.
        if let Some(x) = *mtu {
            use crate::msgs::fragmenter;
            debug_assert!(x > fragmenter::PACKET_OVERHEAD);
            self.mtu = Some(x - fragmenter::PACKET_OVERHEAD);
        } else {
            self.mtu = None;
        }
    }

    /// Sets a single client authentication certificate and private key.
    /// This is blindly used for all servers that ask for client auth.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates,
    /// `key_der` is a DER-encoded RSA or ECDSA private key.
    pub fn set_single_client_cert(
        &mut self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<(), TlsError> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        self.client_auth_cert_resolver = Arc::new(resolver);
        Ok(())
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig {
        danger::DangerousClientConfig { cfg: self }
    }
}

/// Container for unsafe APIs
#[cfg(feature = "dangerous_configuration")]
pub mod danger {
    use std::sync::Arc;

    use super::verify::ServerCertVerifier;
    use super::ClientConfig;

    /// Accessor for dangerous configuration options.
    pub struct DangerousClientConfig<'a> {
        /// The underlying ClientConfig
        pub cfg: &'a mut ClientConfig,
    }

    impl<'a> DangerousClientConfig<'a> {
        /// Overrides the default `ServerCertVerifier` with something else.
        pub fn set_certificate_verifier(&mut self, verifier: Arc<dyn ServerCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Disabled,
    Ready,
    Accepted,
    AcceptedFinished,
    Rejected,
}

pub struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new() -> EarlyData {
        EarlyData {
            left: 0,
            state: EarlyDataState::Disabled,
        }
    }

    fn is_enabled(&self) -> bool {
        match self.state {
            EarlyDataState::Ready | EarlyDataState::Accepted => true,
            _ => false,
        }
    }

    fn is_accepted(&self) -> bool {
        match self.state {
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished => true,
            _ => false,
        }
    }

    fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    fn accepted(&mut self) {
        trace!("EarlyData accepted");
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Accepted;
    }

    fn finished(&mut self) {
        trace!("EarlyData finished");
        self.state = match self.state {
            EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
            _ => panic!("bad EarlyData state"),
        }
    }

    fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        match self.state {
            EarlyDataState::Disabled => unreachable!(),
            EarlyDataState::Ready | EarlyDataState::Accepted => {
                let take = if self.left < sz {
                    mem::replace(&mut self.left, 0)
                } else {
                    self.left -= sz;
                    sz
                };

                Ok(take)
            }
            EarlyDataState::Rejected | EarlyDataState::AcceptedFinished => {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        }
    }

    fn bytes_left(&self) -> usize {
        self.left
    }
}

/// Stub that implements io::Write and dispatches to `write_early_data`.
pub struct WriteEarlyData<'a> {
    sess: &'a mut ClientSession,
}

impl<'a> WriteEarlyData<'a> {
    fn new(sess: &'a mut ClientSession) -> WriteEarlyData<'a> {
        WriteEarlyData { sess }
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.sess.early_data.bytes_left()
    }
}

impl<'a> io::Write for WriteEarlyData<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sess.write_early_data(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// This represents a single TLS client session.
pub struct ClientSession {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) common: SessionCommon,
    pub(crate) state: Option<hs::NextState>,
    pub(crate) server_cert_chain: CertificatePayload,
    pub(crate) early_data: EarlyData,
    pub(crate) resumption_ciphersuite: Option<&'static SupportedCipherSuite>,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientSession").finish()
    }
}

impl ClientSession {
    /// Make a new ClientSession.  `config` controls how
    /// we behave in the TLS protocol, `hostname` is the
    /// hostname of who we want to talk to.
    pub fn new(
        config: &Arc<ClientConfig>,
        hostname: webpki::DNSNameRef,
    ) -> Result<ClientSession, TlsError> {
        let mut new = Self::from_config(config);
        new.start_handshake(hostname.into(), vec![])?;
        Ok(new)
    }

    pub(crate) fn from_config(config: &Arc<ClientConfig>) -> Self {
        ClientSession {
            config: config.clone(),
            common: SessionCommon::new(config.mtu, true),
            state: None,
            server_cert_chain: Vec::new(),
            early_data: EarlyData::new(),
            resumption_ciphersuite: None,
        }
    }

    /// Returns an `io::Write` implementer you can write bytes to
    /// to send TLS1.3 early data (a.k.a. "0-RTT data") to the server.
    ///
    /// This returns None in many circumstances when the capability to
    /// send early data is not available, including but not limited to:
    ///
    /// - The server hasn't been talked to previously.
    /// - The server does not support resumption.
    /// - The server does not support early data.
    /// - The resumption data for the server has expired.
    ///
    /// The server specifies a maximum amount of early data.  You can
    /// learn this limit through the returned object, and writes through
    /// it will process only this many bytes.
    ///
    /// The server can choose not to accept any sent early data --
    /// in this case the data is lost but the connection continues.  You
    /// can tell this happened using `is_early_data_accepted`.
    pub fn early_data(&mut self) -> Option<WriteEarlyData> {
        if self.early_data.is_enabled() {
            Some(WriteEarlyData::new(self))
        } else {
            None
        }
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data.is_accepted()
    }

    pub(crate) fn start_handshake(
        &mut self,
        dns_name: webpki::DNSName,
        extra_exts: Vec<ClientExtension>,
    ) -> Result<(), TlsError> {
        self.state = Some(hs::start_handshake(self, dns_name, extra_exts)?);
        Ok(())
    }

    fn get_cipher_suites(&self) -> Vec<CipherSuite> {
        let mut ret = Vec::new();

        for cs in &self.config.ciphersuites {
            ret.push(cs.suite);
        }

        // We don't do renegotiation at all, in fact.
        ret.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        ret
    }

    fn find_cipher_suite(&self, suite: CipherSuite) -> Option<&'static SupportedCipherSuite> {
        self.config
            .ciphersuites
            .iter()
            .copied()
            .find(|&scs| scs.suite == suite)
    }

    pub(crate) fn process_new_handshake_messages(&mut self) -> Result<(), TlsError> {
        while let Some(msg) = self
            .common
            .handshake_joiner
            .frames
            .pop_front()
        {
            self.process_main_protocol(msg)?;
        }

        Ok(())
    }

    fn reject_renegotiation_attempt(&mut self) -> Result<(), TlsError> {
        self.common
            .send_warning_alert(AlertDescription::NoRenegotiation);
        Ok(())
    }

    fn queue_unexpected_alert(&mut self) {
        self.common
            .send_fatal_alert(AlertDescription::UnexpectedMessage);
    }

    fn maybe_send_unexpected_alert(&mut self, rc: hs::NextStateOrError) -> hs::NextStateOrError {
        match rc {
            Err(TlsError::InappropriateMessage { .. })
            | Err(TlsError::InappropriateHandshakeMessage { .. }) => {
                self.queue_unexpected_alert();
            }
            _ => {}
        };
        rc
    }

    /// Process `msg`.  First, we get the current state.  Then we ask what messages
    /// that state expects, enforced via `check_message`.  Finally, we ask the handler
    /// to handle the message.
    fn process_main_protocol(&mut self, msg: Message) -> Result<(), TlsError> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if msg.is_handshake_type(HandshakeType::HelloRequest)
            && !self.common.is_tls13()
            && !self.is_handshaking()
        {
            return self.reject_renegotiation_attempt();
        }

        let state = self.state.take().unwrap();
        let maybe_next_state = state.handle(self, msg);
        let next_state = self.maybe_send_unexpected_alert(maybe_next_state)?;
        self.state = Some(next_state);

        Ok(())
    }

    fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
        self.early_data
            .check_write(data.len())
            .and_then(|sz| {
                Ok(self
                    .common
                    .send_early_plaintext(&data[..sz]))
            })
    }

    fn send_some_plaintext(&mut self, buf: &[u8]) -> usize {
        let mut st = self.state.take();
        st.as_mut()
            .map(|st| st.perhaps_write_key_update(self));
        self.state = st;

        self.common.send_some_plaintext(buf)
    }
}

impl Session for ClientSession {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.common.read_tls(rd)
    }

    /// Writes TLS messages to `wr`.
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.common.write_tls(wr)
    }

    fn process_new_packets(&mut self) -> Result<(), TlsError> {
        if let Some(ref err) = self.common.error {
            return Err(err.clone());
        }

        if self.common.message_deframer.desynced {
            return Err(TlsError::CorruptMessage);
        }

        while let Some(msg) = self
            .common
            .message_deframer
            .frames
            .pop_front()
        {
            let ignore_corrupt_payload = false;
            let result = self
                .common
                .process_msg(msg, ignore_corrupt_payload)
                .and_then(|val| match val {
                    Some(MessageType::Handshake) => self.process_new_handshake_messages(),
                    Some(MessageType::Data(msg)) => self.process_main_protocol(msg),
                    None => Ok(()),
                });

            if let Err(err) = result {
                self.common.error = Some(err.clone());
                return Err(err);
            }
        }

        Ok(())
    }

    fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we
        // have unprocessed plaintext.  This provides back-pressure
        // to the TCP buffers.
        //
        // This also covers the handshake case, because we don't have
        // readable plaintext before handshake has completed.
        !self.common.has_readable_plaintext()
    }

    fn wants_write(&self) -> bool {
        !self.common.sendable_tls.is_empty()
    }

    fn is_handshaking(&self) -> bool {
        !self.common.traffic
    }

    fn set_buffer_limit(&mut self, len: usize) {
        self.common.set_buffer_limit(len)
    }

    fn send_close_notify(&mut self) {
        self.common.send_close_notify()
    }

    fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>> {
        if self.server_cert_chain.is_empty() {
            return None;
        }

        Some(
            self.server_cert_chain
                .iter()
                .cloned()
                .collect(),
        )
    }

    fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.common.get_alpn_protocol()
    }

    fn get_protocol_version(&self) -> Option<ProtocolVersion> {
        self.common.negotiated_version
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        self.state
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeNotComplete)
            .and_then(|st| st.export_keying_material(output, label, context))
    }

    fn get_negotiated_ciphersuite(&self) -> Option<&'static SupportedCipherSuite> {
        self.state
            .as_ref()
            .unwrap()
            .suite()
            .or(self.resumption_ciphersuite)
    }
}

impl io::Read for ClientSession {
    /// Obtain plaintext data received from the peer over this TLS connection.
    ///
    /// If the peer closes the TLS session cleanly, this fails with an error of
    /// kind ErrorKind::ConnectionAborted once all the pending data has been read.
    /// No further data can be received on that connection, so the underlying TCP
    /// connection should closed too.
    ///
    /// Note that support close notify varies in peer TLS libraries: many do not
    /// support it and uncleanly close the TCP connection (this might be
    /// vulnerable to truncation attacks depending on the application protocol).
    /// This means applications using rustls must both handle ErrorKind::ConnectionAborted
    /// from this function, *and* unexpected closure of the underlying TCP connection.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common.read(buf)
    }
}

impl io::Write for ClientSession {
    /// Send the plaintext `buf` to the peer, encrypting
    /// and authenticating it.  Once this function succeeds
    /// you should call `write_tls` which will output the
    /// corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the
    /// TLS handshake completes, and sends it as soon
    /// as it can.  This buffer is of *unlimited size* so
    /// writing much data before it can be sent will
    /// cause excess memory usage.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.send_some_plaintext(buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut sz = 0;
        for buf in bufs {
            sz += self.send_some_plaintext(buf);
        }
        Ok(sz)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.common.flush_plaintext();
        Ok(())
    }
}
