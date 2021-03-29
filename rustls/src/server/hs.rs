use crate::error::TlsError;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ExtensionType};
use crate::msgs::enums::{CipherSuite, Compression, ECPointFormat};
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::{ClientExtension, HandshakeMessagePayload};
use crate::msgs::handshake::{ClientHelloPayload, ServerExtension, SessionID};
use crate::msgs::handshake::{ConvertProtocolNameList, ConvertServerNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HandshakePayload, SupportedSignatureSchemes};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::rand;
use crate::server::{ClientHello, ServerConfig, ServerSessionImpl};
#[cfg(feature = "quic")]
use crate::session::Protocol;
use crate::session::{SessionRandoms, SessionSecrets};
use crate::suites;
use webpki;

use crate::server::common::{HandshakeDetails, ServerKXDetails};
use crate::server::{tls12, tls13};

pub type NextState = Box<dyn State + Send + Sync>;
pub type NextStateOrError = Result<NextState, TlsError>;

pub trait State {
    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        Err(TlsError::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _sess: &mut ServerSessionImpl) {}
}

pub fn incompatible(sess: &mut ServerSessionImpl, why: &str) -> TlsError {
    sess.common
        .send_fatal_alert(AlertDescription::HandshakeFailure);
    TlsError::PeerIncompatibleError(why.to_string())
}

fn bad_version(sess: &mut ServerSessionImpl, why: &str) -> TlsError {
    sess.common
        .send_fatal_alert(AlertDescription::ProtocolVersion);
    TlsError::PeerIncompatibleError(why.to_string())
}

pub fn illegal_param(sess: &mut ServerSessionImpl, why: &str) -> TlsError {
    sess.common
        .send_fatal_alert(AlertDescription::IllegalParameter);
    TlsError::PeerMisbehavedError(why.to_string())
}

pub fn decode_error(sess: &mut ServerSessionImpl, why: &str) -> TlsError {
    sess.common
        .send_fatal_alert(AlertDescription::DecodeError);
    TlsError::PeerMisbehavedError(why.to_string())
}

pub fn can_resume(
    sess: &ServerSessionImpl,
    using_ems: bool,
    resumedata: persist::ServerSessionValue,
) -> Option<persist::ServerSessionValue> {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    //
    // RFC 6066 says "A server that implements this extension MUST NOT accept
    // the request to resume the session if the server_name extension contains
    // a different name. Instead, it proceeds with a full handshake to
    // establish a new session."

    if resumedata.cipher_suite == sess.common.get_suite_assert().suite
        && (resumedata.extended_ms == using_ems || (resumedata.extended_ms && !using_ems))
        && same_dns_name_or_both_none(resumedata.sni.as_ref(), sess.sni.as_ref())
    {
        return Some(resumedata);
    }

    None
}

// Require an exact match for the purpose of comparing SNI DNS Names from two
// client hellos, even though a case-insensitive comparison might also be OK.
fn same_dns_name_or_both_none(a: Option<&webpki::DNSName>, b: Option<&webpki::DNSName>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let a: &str = a.as_ref().into();
            let b: &str = b.as_ref().into();
            a == b
        }
        (None, None) => true,
        _ => false,
    }
}

// Changing the keys must not span any fragmented handshake
// messages.  Otherwise the defragmented messages will have
// been protected with two different record layer protections,
// which is illegal.  Not mentioned in RFC.
pub fn check_aligned_handshake(sess: &mut ServerSessionImpl) -> Result<(), TlsError> {
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

pub fn save_sni(sess: &mut ServerSessionImpl, sni: Option<webpki::DNSName>) {
    if let Some(sni) = sni {
        // Save the SNI into the session.
        sess.set_sni(sni);
    }
}

#[derive(Default)]
pub struct ExtensionProcessing {
    // extensions to reply with
    pub exts: Vec<ServerExtension>,

    pub send_ticket: bool,
}

impl ExtensionProcessing {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn process_common(
        &mut self,
        sess: &mut ServerSessionImpl,
        ocsp_response: &mut Option<&[u8]>,
        sct_list: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        handshake: &HandshakeDetails,
    ) -> Result<(), TlsError> {
        // ALPN
        let our_protocols = &sess.config.alpn_protocols;
        let maybe_their_protocols = hello.get_alpn_extension();
        if let Some(their_protocols) = maybe_their_protocols {
            let their_protocols = their_protocols.to_slices();

            if their_protocols
                .iter()
                .any(|protocol| protocol.is_empty())
            {
                return Err(TlsError::PeerMisbehavedError(
                    "client offered empty ALPN protocol".to_string(),
                ));
            }

            sess.common.alpn_protocol = our_protocols
                .iter()
                .find(|protocol| their_protocols.contains(&protocol.as_slice()))
                .cloned();
            if let Some(ref selected_protocol) = sess.common.alpn_protocol {
                debug!("Chosen ALPN protocol {:?}", selected_protocol);
                self.exts
                    .push(ServerExtension::make_alpn(&[selected_protocol]));
            } else {
                // For compatibility, strict ALPN validation is not employed unless targeting QUIC
                #[cfg(feature = "quic")]
                {
                    if sess.common.protocol == Protocol::Quic && !our_protocols.is_empty() {
                        sess.common
                            .send_fatal_alert(AlertDescription::NoApplicationProtocol);
                        return Err(TlsError::NoApplicationProtocol);
                    }
                }
            }
        }

        #[cfg(feature = "quic")]
        {
            if sess.common.protocol == Protocol::Quic {
                if let Some(params) = hello.get_quic_params_extension() {
                    sess.common.quic.params = Some(params);
                }

                if let Some(resume) = resumedata {
                    if sess.config.max_early_data_size > 0
                        && hello.early_data_extension_offered()
                        && resume.version == sess.common.negotiated_version.unwrap()
                        && resume.cipher_suite == sess.common.get_suite_assert().suite
                        && resume.alpn.as_ref().map(|x| &x.0) == sess.common.alpn_protocol.as_ref()
                        && !sess.reject_early_data
                    {
                        self.exts
                            .push(ServerExtension::EarlyData);
                    } else {
                        // Clobber value set in tls13::emit_server_hello
                        sess.common.quic.early_secret = None;
                    }
                }
            }
        }

        let for_resume = resumedata.is_some();
        // SNI
        if !for_resume && hello.get_sni_extension().is_some() {
            self.exts
                .push(ServerExtension::ServerNameAck);
        }

        // Send status_request response if we have one.  This is not allowed
        // if we're resuming, and is only triggered if we have an OCSP response
        // to send.
        if !for_resume
            && hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some()
        {
            if ocsp_response.is_some() && !sess.common.is_tls13() {
                // Only TLS1.2 sends confirmation in ServerHello
                self.exts
                    .push(ServerExtension::CertificateStatusAck);
            }
        } else {
            // Throw away any OCSP response so we don't try to send it later.
            ocsp_response.take();
        }

        if !for_resume
            && hello
                .find_extension(ExtensionType::SCT)
                .is_some()
        {
            if !sess.common.is_tls13() {
                // Take the SCT list, if any, so we don't send it later,
                // and put it in the legacy extension.
                if let Some(sct_list) = sct_list.take() {
                    self.exts
                        .push(ServerExtension::make_sct(sct_list.to_vec()));
                }
            }
        } else {
            // Throw away any SCT list so we don't send it later.
            sct_list.take();
        }

        self.exts
            .extend(handshake.extra_exts.iter().cloned());

        Ok(())
    }

    pub(super) fn process_tls12(
        &mut self,
        sess: &ServerSessionImpl,
        hello: &ClientHelloPayload,
        using_ems: bool,
    ) {
        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        let secure_reneg_offered = hello
            .find_extension(ExtensionType::RenegotiationInfo)
            .is_some()
            || hello
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            self.exts
                .push(ServerExtension::make_empty_renegotiation_info());
        }

        // Tickets:
        // If we get any SessionTicket extension and have tickets enabled,
        // we send an ack.
        if hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
            && sess.config.ticketer.enabled()
        {
            self.send_ticket = true;
            self.exts
                .push(ServerExtension::SessionTicketAck);
        }

        // Confirm use of EMS if offered.
        if using_ems {
            self.exts
                .push(ServerExtension::ExtendedMasterSecretAck);
        }
    }
}

pub struct ExpectClientHello {
    pub handshake: HandshakeDetails,
    pub using_ems: bool,
    pub done_retry: bool,
    pub send_ticket: bool,
}

impl ExpectClientHello {
    pub fn new(
        server_config: &ServerConfig,
        extra_exts: Vec<ServerExtension>,
    ) -> ExpectClientHello {
        let mut ech = ExpectClientHello {
            handshake: HandshakeDetails::new(extra_exts),
            using_ems: false,
            done_retry: false,
            send_ticket: false,
        };

        if server_config
            .verifier
            .offer_client_auth()
        {
            ech.handshake
                .transcript
                .set_client_auth_enabled();
        }

        ech
    }

    fn emit_server_hello_done(&mut self, sess: &mut ServerSessionImpl) {
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHelloDone,
                payload: HandshakePayload::ServerHelloDone,
            }),
        };

        self.handshake
            .transcript
            .add_message(&m);
        sess.common.send_msg(m, false);
    }

    fn start_resumption(
        mut self,
        sess: &mut ServerSessionImpl,
        client_hello: &ClientHelloPayload,
        sni: Option<&webpki::DNSName>,
        id: &SessionID,
        resumedata: persist::ServerSessionValue,
        randoms: &SessionRandoms,
    ) -> NextStateOrError {
        debug!("Resuming session");

        if resumedata.extended_ms && !self.using_ems {
            return Err(illegal_param(sess, "refusing to resume without ems"));
        }

        self.handshake.session_id = *id;
        self.send_ticket = tls12::emit_server_hello(
            &mut self.handshake,
            sess,
            self.using_ems,
            &mut None,
            &mut None,
            client_hello,
            Some(&resumedata),
            randoms,
        )?;

        let suite = sess.common.get_suite_assert();
        let secrets = SessionSecrets::new_resume(&randoms, suite, &resumedata.master_secret.0);
        sess.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        sess.common
            .start_encryption_tls12(&secrets);
        sess.client_cert_chain = resumedata.client_cert_chain;

        if self.send_ticket {
            tls12::emit_ticket(&secrets, &mut self.handshake, self.using_ems, sess);
        }
        tls12::emit_ccs(sess);
        sess.common
            .record_layer
            .start_encrypting();
        tls12::emit_finished(&secrets, &mut self.handshake, sess);

        assert!(same_dns_name_or_both_none(sni, sess.get_sni()));

        Ok(Box::new(tls12::ExpectCCS {
            secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            resuming: true,
            send_ticket: self.send_ticket,
        }))
    }
}

impl State for ExpectClientHello {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
        let tls13_enabled = sess
            .config
            .supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = sess
            .config
            .supports_version(ProtocolVersion::TLSv1_2);
        trace!("we got a clienthello {:?}", client_hello);

        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            sess.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(TlsError::PeerIncompatibleError(
                "client did not offer Null compression".to_string(),
            ));
        }

        if client_hello.has_duplicate_extension() {
            return Err(decode_error(sess, "client sent duplicate extensions"));
        }

        // No handshake messages should follow this one in this flight.
        check_aligned_handshake(sess)?;

        // Are we doing TLS1.3?
        let maybe_versions_ext = client_hello.get_versions_extension();
        let version = if let Some(versions) = maybe_versions_ext {
            if versions.contains(&ProtocolVersion::TLSv1_3) && tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Err(bad_version(sess, "TLS1.2 not offered/enabled"));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
            return Err(bad_version(sess, "Client does not support TLSv1_2"));
        } else if !tls12_enabled && tls13_enabled {
            return Err(bad_version(
                sess,
                "Server requires TLS1.3, but client omitted versions ext",
            ));
        } else {
            ProtocolVersion::TLSv1_2
        };

        sess.common.negotiated_version = Some(version);

        // --- Common to TLS1.2 and TLS1.3: ciphersuite and certificate selection.

        // Extract and validate the SNI DNS name, if any, before giving it to
        // the cert resolver. In particular, if it is invalid then we should
        // send an Illegal Parameter alert instead of the Internal Error alert
        // (or whatever) that we'd send if this were checked later or in a
        // different way.
        let sni: Option<webpki::DNSName> = match client_hello.get_sni_extension() {
            Some(sni) => {
                if sni.has_duplicate_names_for_type() {
                    return Err(decode_error(
                        sess,
                        "ClientHello SNI contains duplicate name types",
                    ));
                }

                if let Some(hostname) = sni.get_single_hostname() {
                    Some(hostname.into())
                } else {
                    return Err(illegal_param(
                        sess,
                        "ClientHello SNI did not contain a hostname",
                    ));
                }
            }
            None => None,
        };

        if !self.done_retry {
            // save only the first SNI
            save_sni(sess, sni.clone());
        }

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let mut common_suites = sess.config.ciphersuites.clone();
        common_suites.retain(|scs| {
            client_hello
                .cipher_suites
                .contains(&scs.suite)
        });

        let mut sigschemes_ext = client_hello
            .get_sigalgs_extension()
            .cloned()
            .unwrap_or_else(SupportedSignatureSchemes::default);
        sigschemes_ext
            .retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &common_suites));

        let alpn_protocols = client_hello
            .get_alpn_extension()
            .map(|protos| protos.to_slices());

        // Choose a certificate.
        let certkey = {
            let sni_ref = sni
                .as_ref()
                .map(webpki::DNSName::as_ref);
            trace!("sni {:?}", sni_ref);
            trace!("sig schemes {:?}", sigschemes_ext);
            trace!("alpn protocols {:?}", alpn_protocols);

            let alpn_slices = alpn_protocols
                .as_ref()
                .map(|vec| vec.as_slice());

            let client_hello = ClientHello::new(sni_ref, &sigschemes_ext, alpn_slices);

            let certkey = sess
                .config
                .cert_resolver
                .resolve(client_hello);
            certkey.ok_or_else(|| {
                sess.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                TlsError::General("no server certificate chain resolved".to_string())
            })?
        };

        // Reduce our supported ciphersuites by the certificate.
        // (no-op for TLS1.3)
        let suitable_suites =
            suites::reduce_given_sigalg(&sess.config.ciphersuites, certkey.key.algorithm());

        // And version
        let suitable_suites = suites::reduce_given_version(&suitable_suites, version);

        let ciphersuite = if sess.config.ignore_client_order {
            suites::choose_ciphersuite_preferring_server(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        } else {
            suites::choose_ciphersuite_preferring_client(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        }
        .ok_or_else(|| incompatible(sess, "no ciphersuites in common"))?;

        debug!("decided upon suite {:?}", ciphersuite);
        sess.common.set_suite(ciphersuite);

        // Start handshake hash.
        let starting_hash = sess
            .common
            .get_suite_assert()
            .get_hash();
        if !self
            .handshake
            .transcript
            .start_hash(starting_hash)
        {
            sess.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(TlsError::PeerIncompatibleError(
                "hash differed on retry".to_string(),
            ));
        }

        // Save their Random.
        let mut randoms = SessionRandoms::for_server()?;
        client_hello
            .random
            .write_slice(&mut randoms.client);

        if sess.common.is_tls13() {
            return tls13::CompleteClientHelloHandling {
                handshake: self.handshake,
                randoms,
                done_retry: self.done_retry,
                send_ticket: self.send_ticket,
            }
            .handle_client_hello(ciphersuite, sess, &certkey, &m);
        }

        // -- TLS1.2 only from hereon in --
        self.handshake
            .transcript
            .add_message(&m);

        if client_hello.ems_support_offered() {
            self.using_ems = true;
        }

        let groups_ext = client_hello
            .get_namedgroups_extension()
            .ok_or_else(|| incompatible(sess, "client didn't describe groups"))?;
        let ecpoints_ext = client_hello
            .get_ecpoints_extension()
            .ok_or_else(|| incompatible(sess, "client didn't describe ec points"))?;

        trace!("namedgroups {:?}", groups_ext);
        trace!("ecpoints {:?}", ecpoints_ext);

        if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
            sess.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(TlsError::PeerIncompatibleError(
                "client didn't support uncompressed ec points".to_string(),
            ));
        }

        // -- If TLS1.3 is enabled, signal the downgrade in the server random
        if tls13_enabled {
            randoms.set_tls12_downgrade_marker();
        }

        // -- Check for resumption --
        // We can do this either by (in order of preference):
        // 1. receiving a ticket that decrypts
        // 2. receiving a sessionid that is in our cache
        //
        // If we receive a ticket, the sessionid won't be in our
        // cache, so don't check.
        //
        // If either works, we end up with a ServerSessionValue
        // which is passed to start_resumption and concludes
        // our handling of the ClientHello.
        //
        let mut ticket_received = false;

        if let Some(ticket_ext) = client_hello.get_ticket_extension() {
            if let ClientExtension::SessionTicketOffer(ref ticket) = *ticket_ext {
                ticket_received = true;
                debug!("Ticket received");

                if let Some(resume) = sess
                    .config
                    .ticketer
                    .decrypt(&ticket.0)
                    .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
                    .and_then(|resumedata| can_resume(sess, self.using_ems, resumedata))
                {
                    return self.start_resumption(
                        sess,
                        client_hello,
                        sni.as_ref(),
                        &client_hello.session_id,
                        resume,
                        &randoms,
                    );
                } else {
                    debug!("Ticket didn't decrypt");
                }
            }
        }

        // If we're not offered a ticket or a potential session ID,
        // allocate a session ID.
        if self.handshake.session_id.is_empty() && !ticket_received {
            let mut bytes = [0u8; 32];
            rand::fill_random(&mut bytes)?;
            self.handshake.session_id = SessionID::new(&bytes);
        }

        // Perhaps resume?  If we received a ticket, the sessionid
        // does not correspond to a real session.
        if !client_hello.session_id.is_empty() && !ticket_received {
            if let Some(resume) = sess
                .config
                .session_storage
                .get(&client_hello.session_id.get_encoding())
                .and_then(|x| persist::ServerSessionValue::read_bytes(&x))
                .and_then(|resumedata| can_resume(sess, self.using_ems, resumedata))
            {
                return self.start_resumption(
                    sess,
                    client_hello,
                    sni.as_ref(),
                    &client_hello.session_id,
                    resume,
                    &randoms,
                );
            }
        }

        // Now we have chosen a ciphersuite, we can make kx decisions.
        let sigschemes = sess
            .common
            .get_suite_assert()
            .resolve_sig_schemes(&sigschemes_ext);

        if sigschemes.is_empty() {
            return Err(incompatible(sess, "no supported sig scheme"));
        }

        let group = sess
            .config
            .kx_groups
            .iter()
            .find(|skxg| groups_ext.contains(&skxg.name))
            .cloned()
            .ok_or_else(|| incompatible(sess, "no supported group"))?;

        let ecpoint = ECPointFormatList::supported()
            .iter()
            .find(|format| ecpoints_ext.contains(format))
            .cloned()
            .ok_or_else(|| incompatible(sess, "no supported point format"))?;

        debug_assert_eq!(ecpoint, ECPointFormat::Uncompressed);

        let (mut ocsp_response, mut sct_list) =
            (certkey.ocsp.as_deref(), certkey.sct_list.as_deref());
        self.send_ticket = tls12::emit_server_hello(
            &mut self.handshake,
            sess,
            self.using_ems,
            &mut ocsp_response,
            &mut sct_list,
            client_hello,
            None,
            &randoms,
        )?;
        tls12::emit_certificate(&mut self.handshake, sess, &certkey.cert);
        if let Some(ocsp_response) = ocsp_response {
            tls12::emit_cert_status(&mut self.handshake, sess, ocsp_response);
        }
        let kx = tls12::emit_server_kx(
            &mut self.handshake,
            sess,
            sigschemes,
            group,
            &certkey.key,
            &randoms,
        )?;
        let doing_client_auth = tls12::emit_certificate_req(&mut self.handshake, sess)?;
        self.emit_server_hello_done(sess);

        let server_kx = ServerKXDetails::new(kx);
        if doing_client_auth {
            Ok(Box::new(tls12::ExpectCertificate {
                handshake: self.handshake,
                randoms,
                using_ems: self.using_ems,
                server_kx,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(tls12::ExpectClientKX {
                handshake: self.handshake,
                randoms,
                using_ems: self.using_ems,
                server_kx,
                client_cert: None,
                send_ticket: self.send_ticket,
            }))
        }
    }
}
