#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::check_message;
use crate::client::ClientSession;
use crate::error::TlsError;
use crate::hash_hs::HandshakeHash;
use crate::key_schedule::KeyScheduleEarly;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
#[cfg(feature = "quic")]
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, Compression, ProtocolVersion};
use crate::msgs::enums::{ContentType, ExtensionType, HandshakeType};
use crate::msgs::enums::{ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::handshake::HelloRetryRequest;
use crate::msgs::handshake::{CertificateStatusRequest, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{Random, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::rand;
use crate::session::{SessionRandoms, SessionSecrets};
use crate::ticketer;
use crate::verify;

use crate::client::common::HandshakeDetails;
use crate::client::common::{ClientHelloDetails, ReceivedTicketDetails};
use crate::client::{tls12, tls13};

use webpki;

pub type NextState = Box<dyn State + Send + Sync>;
pub type NextStateOrError = Result<NextState, TlsError>;

pub trait State {
    /// Each handle() implementation consumes a whole TLS message, and returns
    /// either an error or the next state.
    fn handle(self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextStateOrError;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        Err(TlsError::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _sess: &mut ClientSession) {}
}

pub fn illegal_param(sess: &mut ClientSession, why: &str) -> TlsError {
    sess.common
        .send_fatal_alert(AlertDescription::IllegalParameter);
    TlsError::PeerMisbehavedError(why.to_string())
}

pub fn check_aligned_handshake(sess: &mut ClientSession) -> Result<(), TlsError> {
    if !sess.common.handshake_joiner.is_empty() {
        sess.common
            .send_fatal_alert(AlertDescription::UnexpectedMessage);
        Err(TlsError::PeerMisbehavedError(
            "key epoch or handshake flight with pending fragment".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn find_session(
    sess: &mut ClientSession,
    dns_name: webpki::DNSNameRef,
) -> Option<persist::ClientSessionValueWithResolvedCipherSuite> {
    let key = persist::ClientSessionKey::session_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let value = sess
        .config
        .session_persistence
        .get(&key_buf)
        .or_else(|| {
            debug!("No cached session for {:?}", dns_name);
            None
        })?;

    let mut reader = Reader::init(&value[..]);
    let result = persist::ClientSessionValue::read(&mut reader)
        .and_then(|csv| csv.resolve_cipher_suite(&sess.config.ciphersuites));
    if let Some(result) = result {
        if result.has_expired(ticketer::timebase()) {
            None
        } else {
            #[cfg(feature = "quic")]
            {
                if sess.common.is_quic() {
                    let params = PayloadU16::read(&mut reader)?;
                    sess.common.quic.params = Some(params.0);
                }
            }
            Some(result)
        }
    } else {
        None
    }
}

fn random_sessionid() -> Result<SessionID, rand::GetRandomFailed> {
    let mut random_id = [0u8; 32];
    rand::fill_random(&mut random_id)?;
    Ok(SessionID::new(&random_id))
}

struct InitialState {
    handshake: HandshakeDetails,
    dns_name: webpki::DNSName,
    transcript: HandshakeHash,
    extra_exts: Vec<ClientExtension>,
}

impl InitialState {
    fn new(dns_name: webpki::DNSName, extra_exts: Vec<ClientExtension>) -> InitialState {
        InitialState {
            handshake: HandshakeDetails::new(),
            dns_name,
            transcript: HandshakeHash::new(),
            extra_exts,
        }
    }

    fn emit_initial_client_hello(mut self, sess: &mut ClientSession) -> NextStateOrError {
        // During retries "the client MUST send the same ClientHello without
        // modification" with only a few exceptions as noted in
        // https://tools.ietf.org/html/rfc8446#section-4.1.2,
        // Calculate all inputs to the client hellos that might otherwise
        // change between the initial and retry hellos here to enforce this.

        if sess
            .config
            .client_auth_cert_resolver
            .has_certs()
        {
            self.transcript
                .set_client_auth_enabled();
        }

        let mut session_id: Option<SessionID> = None;
        self.handshake.resuming_session = find_session(sess, self.dns_name.as_ref());

        if let Some(resuming) = &mut self.handshake.resuming_session {
            if resuming.version == ProtocolVersion::TLSv1_2 {
                // If we have a ticket, we use the sessionid as a signal that
                // we're  doing an abbreviated handshake.  See section 3.4 in
                // RFC5077.
                if !resuming.ticket.0.is_empty() {
                    resuming.set_session_id(random_sessionid()?);
                }
                session_id = Some(resuming.session_id);
            }
            debug!("Resuming session");
        } else {
            debug!("Not resuming any session");
        }
        // https://tools.ietf.org/html/rfc8446#appendix-D.4
        // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
        if session_id.is_none() && !sess.common.is_quic() {
            session_id = Some(random_sessionid()?);
        }

        let randoms = SessionRandoms::for_client()?;
        let hello_details = ClientHelloDetails::new();
        let sent_tls13_fake_ccs = false;
        let may_send_sct_list = sess.config.verifier.request_scts();
        emit_client_hello_for_retry(
            sess,
            self.handshake,
            randoms,
            false,
            self.transcript,
            sent_tls13_fake_ccs,
            hello_details,
            session_id,
            None,
            self.dns_name,
            self.extra_exts,
            may_send_sct_list,
        )
    }
}

pub fn start_handshake(
    sess: &mut ClientSession,
    host_name: webpki::DNSName,
    extra_exts: Vec<ClientExtension>,
) -> NextStateOrError {
    InitialState::new(host_name, extra_exts).emit_initial_client_hello(sess)
}

struct ExpectServerHello {
    handshake: HandshakeDetails,
    dns_name: webpki::DNSName,
    randoms: SessionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    early_key_schedule: Option<KeyScheduleEarly>,
    hello: ClientHelloDetails,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

fn emit_client_hello_for_retry(
    sess: &mut ClientSession,
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    mut transcript: HandshakeHash,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: Option<SessionID>,
    retryreq: Option<&HelloRetryRequest>,
    dns_name: webpki::DNSName,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
) -> NextStateOrError {
    // Do we have a SessionID or ticket cached for this host?
    let (ticket, resume_version) = if let Some(resuming) = &handshake.resuming_session {
        (resuming.ticket.0.clone(), resuming.version)
    } else {
        (Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = sess
        .config
        .supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = sess
        .config
        .supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    if sess.config.enable_sni {
        exts.push(ClientExtension::make_sni(dns_name.as_ref()));
    }
    exts.push(ClientExtension::ECPointFormats(
        ECPointFormatList::supported(),
    ));
    exts.push(ClientExtension::NamedGroups(
        sess.config
            .kx_groups
            .iter()
            .map(|skxg| skxg.name)
            .collect(),
    ));
    exts.push(ClientExtension::SignatureAlgorithms(
        sess.config
            .get_verifier()
            .supported_verify_schemes(),
    ));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);
    exts.push(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::build_ocsp(),
    ));

    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if support_tls13 {
        tls13::choose_kx_groups(sess, &mut exts, &mut hello, dns_name.as_ref(), retryreq);
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && sess.config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !sess.config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &sess
                .config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(extra_exts.iter().cloned());

    let fill_in_binder = if support_tls13
        && sess.config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        handshake
            .resuming_session
            .as_ref()
            .filter(|resuming| match sess.common.get_suite() {
                Some(suite) => suite.can_resume_to(&resuming.supported_cipher_suite()),
                None => true,
            })
            .map(|resuming| {
                tls13::prepare_resumption(sess, ticket, resuming, &mut exts, retryreq.is_some());
                resuming
            })
    } else if sess.config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicketRequest);
        } else {
            exts.push(ClientExtension::SessionTicketOffer(Payload::new(ticket)));
        }
        None
    } else {
        None
    };

    // Note what extensions we sent.
    hello.sent_extensions = exts
        .iter()
        .map(ClientExtension::get_type)
        .collect();

    let session_id = session_id.unwrap_or(SessionID::empty());

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_slice(&randoms.client),
            session_id: session_id,
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    let early_key_schedule = if let Some(resuming) = fill_in_binder {
        let schedule = tls13::fill_in_psk_binder(&resuming, &transcript, &mut chp);
        Some((resuming, schedule))
    } else {
        None
    };

    let ch = Message {
        typ: ContentType::Handshake,
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, sess);
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript.add_message(&ch);
    sess.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_key_schedule = early_key_schedule.map(|(resuming, schedule)| {
        if !sess.early_data.is_enabled() {
            return schedule;
        }

        tls13::derive_early_traffic_secret(
            sess,
            resuming,
            &schedule,
            &mut sent_tls13_fake_ccs,
            &transcript,
            &randoms.client,
        );
        schedule
    });

    let next = ExpectServerHello {
        handshake,
        dns_name,
        randoms,
        using_ems,
        transcript,
        hello,
        session_id: session_id,
        early_key_schedule,
        sent_tls13_fake_ccs,
    };

    Ok(if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next, extra_exts })
    } else {
        Box::new(next)
    })
}

pub fn process_alpn_protocol(
    sess: &mut ClientSession,
    proto: Option<&[u8]>,
) -> Result<(), TlsError> {
    sess.common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &sess.common.alpn_protocol {
        if !sess
            .config
            .alpn_protocols
            .contains(alpn_protocol)
        {
            return Err(illegal_param(sess, "server sent non-offered ALPN protocol"));
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        sess.common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(&v))
    );
    Ok(())
}

pub fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl State for ExpectServerHello {
    fn handle(mut self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = sess.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if sess.config.supports_version(TLSv1_2) => {
                if sess.early_data.is_enabled() && sess.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(TlsError::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }

                if server_hello
                    .get_supported_versions()
                    .is_some()
                {
                    return Err(illegal_param(
                        sess,
                        "server chose v1.2 using v1.3 extension",
                    ));
                }

                TLSv1_2
            }
            _ => {
                sess.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                return Err(TlsError::PeerIncompatibleError(
                    "server does not support TLS v1.2/v1.3".to_string(),
                ));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(illegal_param(sess, "server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            sess.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(TlsError::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TlsError::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        sess.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !sess.common.is_tls13() {
            process_alpn_protocol(sess, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                sess.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(TlsError::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let suite = sess
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                sess.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                TlsError::PeerMisbehavedError("server chose non-offered ciphersuite".to_string())
            })?;

        debug!("Using ciphersuite {:?}", server_hello.cipher_suite);
        match sess.common.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(illegal_param(sess, "server varied selected ciphersuite"));
            }
            _ => {
                sess.common.suite = Some(suite);
            }
        }

        if !suite.usable_for_version(version) {
            return Err(illegal_param(
                sess,
                "server chose unusable ciphersuite for version",
            ));
        }

        // Start our handshake hash, and input the server-hello.
        self.transcript
            .start_hash(suite.get_hash());
        self.transcript.add_message(&m);

        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        if sess.common.is_tls13() {
            tls13::validate_server_hello(sess, &server_hello)?;
            let (key_schedule, hash_at_client_recvd_server_hello) = tls13::start_handshake_traffic(
                suite,
                sess,
                self.early_key_schedule.take(),
                &server_hello,
                &mut self.handshake,
                self.dns_name.as_ref(),
                &mut self.transcript,
                &mut self.hello,
                &mut self.randoms,
            )?;
            tls13::emit_fake_ccs(&mut self.sent_tls13_fake_ccs, sess);

            return Ok(Box::new(tls13::ExpectEncryptedExtensions {
                handshake: self.handshake,
                dns_name: self.dns_name,
                randoms: self.randoms,
                transcript: self.transcript,
                key_schedule,
                hello: self.hello,
                hash_at_client_recvd_server_hello,
            }));
        }

        // TLS1.2 only from here-on

        // Save ServerRandom and SessionID
        server_hello
            .random
            .write_slice(&mut self.randoms.server);
        self.session_id = server_hello.session_id;

        // Look for TLS1.3 downgrade signal in server random
        if tls13_supported
            && self
                .randoms
                .has_tls12_downgrade_marker()
        {
            return Err(illegal_param(
                sess,
                "downgrade to TLS1.2 when TLS1.3 is supported",
            ));
        }

        // Doing EMS?
        self.using_ems = server_hello.ems_support_acked();

        // Might the server send a ticket?
        let must_issue_new_ticket = if server_hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
        {
            debug!("Server supports tickets");
            true
        } else {
            false
        };

        // Might the server send a CertificateStatus between Certificate and
        // ServerKeyExchange?
        let may_send_cert_status = server_hello
            .find_extension(ExtensionType::StatusRequest)
            .is_some();
        if may_send_cert_status {
            debug!("Server may staple OCSP response");
        }

        // Save any sent SCTs for verification against the certificate.
        let server_cert_sct_list = if let Some(sct_list) = server_hello.get_sct_list() {
            debug!("Server sent {:?} SCTs", sct_list.len());

            if sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(TlsError::PeerMisbehavedError(error_msg));
            }
            Some(sct_list.clone())
        } else {
            None
        };

        // See if we're successfully resuming.
        if let Some(ref resuming) = self.handshake.resuming_session {
            if resuming.session_id == self.session_id {
                debug!("Server agreed to resume");

                // Is the server telling lies about the ciphersuite?
                if resuming.supported_cipher_suite() != suite {
                    let error_msg = "abbreviated handshake offered, but with varied cs".to_string();
                    return Err(TlsError::PeerMisbehavedError(error_msg));
                }

                // And about EMS support?
                if resuming.extended_ms != self.using_ems {
                    let error_msg = "server varied ems support over resume".to_string();
                    return Err(TlsError::PeerMisbehavedError(error_msg));
                }

                let secrets =
                    SessionSecrets::new_resume(&self.randoms, suite, &resuming.master_secret.0);
                sess.config.key_log.log(
                    "CLIENT_RANDOM",
                    &secrets.randoms.client,
                    &secrets.master_secret,
                );
                sess.common
                    .start_encryption_tls12(&secrets);

                // Since we're resuming, we verified the certificate and
                // proof of possession in the prior session.
                sess.server_cert_chain = resuming.server_cert_chain.clone();
                let cert_verified = verify::ServerCertVerified::assertion();
                let sig_verified = verify::HandshakeSignatureValid::assertion();

                return if must_issue_new_ticket {
                    Ok(Box::new(tls12::ExpectNewTicket {
                        secrets,
                        handshake: self.handshake,
                        session_id: self.session_id,
                        dns_name: self.dns_name,
                        using_ems: self.using_ems,
                        transcript: self.transcript,
                        resuming: true,
                        cert_verified,
                        sig_verified,
                    }))
                } else {
                    Ok(Box::new(tls12::ExpectCCS {
                        secrets,
                        handshake: self.handshake,
                        session_id: self.session_id,
                        dns_name: self.dns_name,
                        using_ems: self.using_ems,
                        transcript: self.transcript,
                        ticket: ReceivedTicketDetails::new(),
                        resuming: true,
                        cert_verified,
                        sig_verified,
                    }))
                };
            }
        }

        Ok(Box::new(tls12::ExpectCertificate {
            handshake: self.handshake,
            session_id: self.session_id,
            dns_name: self.dns_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite,
            may_send_cert_status,
            must_issue_new_ticket,
            server_cert_sct_list,
        }))
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        mut self,
        sess: &mut ClientSession,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        check_aligned_handshake(sess)?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none()
            && req_group
                .map(|g| self.next.hello.has_key_share(g))
                .unwrap_or(false)
        {
            return Err(illegal_param(sess, "server requested hrr with our group"));
        }

        // Or asks for us to retry on an unsupported group.
        if let Some(group) = req_group {
            if sess
                .config
                .kx_groups
                .iter()
                .find(|skxg| skxg.name == group)
                .is_none()
            {
                return Err(illegal_param(sess, "server requested hrr with bad group"));
            }
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(illegal_param(
                    sess,
                    "server requested hrr with empty cookie",
                ));
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TlsError::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(illegal_param(sess, "server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(illegal_param(sess, "server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(illegal_param(
                    sess,
                    "server requested unsupported version in hrr",
                ));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = sess.find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(illegal_param(
                    sess,
                    "server requested unsupported cs in hrr",
                ));
            }
        };

        // HRR selects the ciphersuite.
        sess.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        self.next
            .transcript
            .start_hash(cs.get_hash());
        self.next.transcript.rollup_for_hrr();
        self.next.transcript.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if sess.early_data.is_enabled() {
            sess.early_data.rejected();
        }

        let may_send_sct_list = self
            .next
            .hello
            .server_may_send_sct_list();
        emit_client_hello_for_retry(
            sess,
            self.next.handshake,
            self.next.randoms,
            self.next.using_ems,
            self.next.transcript,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            Some(self.next.session_id),
            Some(&hrr),
            self.next.dns_name,
            self.extra_exts,
            may_send_sct_list,
        )
    }
}

impl State for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, sess: &mut ClientSession, m: Message) -> NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
        )?;
        if m.is_handshake_type(HandshakeType::ServerHello) {
            self.into_expect_server_hello()
                .handle(sess, m)
        } else {
            self.handle_hello_retry_request(sess, m)
        }
    }
}

pub fn send_cert_error_alert(sess: &mut ClientSession, err: TlsError) -> TlsError {
    match err {
        TlsError::WebPKIError(webpki::Error::BadDER, _) => {
            sess.common
                .send_fatal_alert(AlertDescription::DecodeError);
        }
        TlsError::PeerMisbehavedError(_) => {
            sess.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            sess.common
                .send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}
