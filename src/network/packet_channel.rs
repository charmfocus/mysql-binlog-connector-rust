#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(all(feature = "rustls", feature = "openssl-tls"))]
compile_error!("features 'rustls' and 'openssl-tls' are mutually exclusive");

#[cfg(feature = "rustls")]
use std::net::IpAddr;
use std::{
    io::{Cursor, Write},
    time::Duration,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpStream, time::timeout};

use crate::binlog_error::BinlogError;

/// close/shutdown 的超时兜底：对端静默丢包（连接半开）时 shutdown() 可能
/// 永久挂起（生产实证：跳板机链路假死，2026-07-21 日志定位）。
/// 超时后放弃优雅关闭，socket fd 随 PacketChannel drop 强制释放。
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(feature = "openssl-tls")]
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
#[cfg(feature = "rustls")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "rustls")]
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
#[cfg(feature = "rustls")]
use std::sync::Arc;
#[cfg(feature = "openssl-tls")]
use tokio_openssl::SslStream as OpenSslStream;
#[cfg(feature = "rustls")]
use tokio_rustls::client::TlsStream;
#[cfg(feature = "rustls")]
use tokio_rustls::TlsConnector;

const MAX_PACKET_LENGTH: usize = 16777215;

enum ChannelStream {
    Plain(TcpStream),
    #[cfg(feature = "rustls")]
    TlsRustls(Box<TlsStream<TcpStream>>),
    #[cfg(feature = "openssl-tls")]
    TlsOpenSsl(Box<OpenSslStream<TcpStream>>),
}

pub struct PacketChannel {
    stream: Option<ChannelStream>,
    timeout_secs: u64,
}

pub struct KeepAliveConfig {
    pub keepidle_secs: u64,
    pub keepintvl_secs: u64,
}

#[cfg(feature = "rustls")]
#[derive(Debug)]
struct NoCertificateVerification;

#[cfg(feature = "rustls")]
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl PacketChannel {
    #[cfg(test)]
    pub fn new_for_test(stream: tokio::net::TcpStream, timeout_secs: u64) -> Self {
        Self {
            stream: Some(ChannelStream::Plain(stream)),
            timeout_secs,
        }
    }

    pub async fn new(
        ip: &str,
        port: &str,
        timeout_secs: u64,
        keepalive_config: &Option<KeepAliveConfig>,
    ) -> Result<Self, BinlogError> {
        let addr = format!("{}:{}", ip, port);
        let stream =
            match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(BinlogError::from(e)),
                Err(_) => {
                    return Err(BinlogError::ConnectError(format!(
                        "Connection timeout after {} seconds while connecting to {}",
                        timeout_secs, addr
                    )))
                }
            };

        if let Some(config) = keepalive_config {
            Self::configure_keepalive(&stream, config)?;
        }

        Ok(Self {
            stream: Some(ChannelStream::Plain(stream)),
            timeout_secs,
        })
    }

    /// Configure TCP keepalive settings for the stream
    /// This is safe because:
    /// 1. We only borrow the stream temporarily
    /// 2. set_tcp_keepalive is a fast syscall (setsockopt) that doesn't block
    /// 3. Keepalive is handled by the kernel, doesn't affect async operations
    fn configure_keepalive(
        stream: &TcpStream,
        config: &KeepAliveConfig,
    ) -> Result<(), BinlogError> {
        if config.keepidle_secs == 0 || config.keepintvl_secs == 0 {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use socket2::{SockRef, TcpKeepalive};
            use std::os::unix::io::BorrowedFd;

            let raw_fd = stream.as_raw_fd();
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let socket_ref = SockRef::from(&borrowed_fd);

            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(config.keepidle_secs))
                .with_interval(Duration::from_secs(config.keepintvl_secs));

            socket_ref
                .set_tcp_keepalive(&keepalive)
                .map_err(BinlogError::IoError)?;
        }

        #[cfg(windows)]
        {
            use socket2::{SockRef, TcpKeepalive};
            use std::os::windows::io::BorrowedSocket;

            let raw_socket = stream.as_raw_socket();
            let borrowed_socket = unsafe { BorrowedSocket::borrow_raw(raw_socket) };
            let socket_ref = SockRef::from(&borrowed_socket);

            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(config.keepidle_secs))
                .with_interval(Duration::from_secs(config.keepintvl_secs));

            socket_ref
                .set_tcp_keepalive(&keepalive)
                .map_err(BinlogError::IoError)?;
        }

        Ok(())
    }

    pub fn is_secure_transport(&self) -> bool {
        match self.stream.as_ref() {
            Some(ChannelStream::Plain(_)) => false,
            #[cfg(feature = "rustls")]
            Some(ChannelStream::TlsRustls(_)) => true,
            #[cfg(feature = "openssl-tls")]
            Some(ChannelStream::TlsOpenSsl(_)) => true,
            None => false,
        }
    }

    #[cfg(feature = "rustls")]
    pub async fn upgrade_to_tls(&mut self, host: &str) -> Result<(), BinlogError> {
        let plain_stream = match self.stream.take() {
            Some(ChannelStream::Plain(stream)) => stream,
            Some(ChannelStream::TlsRustls(stream)) => {
                self.stream = Some(ChannelStream::TlsRustls(stream));
                return Ok(());
            }
            #[cfg(feature = "openssl-tls")]
            Some(ChannelStream::TlsOpenSsl(stream)) => {
                self.stream = Some(ChannelStream::TlsOpenSsl(stream));
                return Ok(());
            }
            None => {
                return Err(BinlogError::ConnectError(
                    "cannot upgrade a disconnected channel to tls".into(),
                ))
            }
        };

        let server_name = Self::build_server_name(host)?;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let tls_stream = connector
            .connect(server_name, plain_stream)
            .await
            .map_err(|e| BinlogError::ConnectError(format!("tls handshake failed: {}", e)))?;

        self.stream = Some(ChannelStream::TlsRustls(Box::new(tls_stream)));
        Ok(())
    }

    #[cfg(feature = "rustls")]
    fn build_server_name(host: &str) -> Result<ServerName<'static>, BinlogError> {
        if let Ok(ip_addr) = host.parse::<IpAddr>() {
            return Ok(ServerName::IpAddress(ip_addr.into()));
        }

        ServerName::try_from(host.to_string())
            .map_err(|_| BinlogError::ConnectError(format!("invalid tls server name: {}", host)))
    }

    #[cfg(not(feature = "rustls"))]
    #[cfg(feature = "openssl-tls")]
    pub async fn upgrade_to_tls(&mut self, host: &str) -> Result<(), BinlogError> {
        let plain_stream = match self.stream.take() {
            Some(ChannelStream::Plain(stream)) => stream,
            #[cfg(feature = "rustls")]
            Some(ChannelStream::TlsRustls(stream)) => {
                self.stream = Some(ChannelStream::TlsRustls(stream));
                return Ok(());
            }
            Some(ChannelStream::TlsOpenSsl(stream)) => {
                self.stream = Some(ChannelStream::TlsOpenSsl(stream));
                return Ok(());
            }
            None => {
                return Err(BinlogError::ConnectError(
                    "cannot upgrade a disconnected channel to tls".into(),
                ))
            }
        };

        let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
            BinlogError::ConnectError(format!("failed to build openssl connector: {}", e))
        })?;
        builder.set_verify(SslVerifyMode::NONE);

        let ssl = builder
            .build()
            .configure()
            .map_err(|e| {
                BinlogError::ConnectError(format!("failed to configure openssl connector: {}", e))
            })?
            .into_ssl(host)
            .map_err(|e| {
                BinlogError::ConnectError(format!("failed to prepare openssl session: {}", e))
            })?;

        let mut tls_stream = OpenSslStream::new(ssl, plain_stream).map_err(|e| {
            BinlogError::ConnectError(format!("failed to create openssl stream: {}", e))
        })?;
        std::pin::Pin::new(&mut tls_stream)
            .connect()
            .await
            .map_err(|e| BinlogError::ConnectError(format!("tls handshake failed: {}", e)))?;

        self.stream = Some(ChannelStream::TlsOpenSsl(Box::new(tls_stream)));
        Ok(())
    }

    #[cfg(not(any(feature = "rustls", feature = "openssl-tls")))]
    pub async fn upgrade_to_tls(&mut self, _host: &str) -> Result<(), BinlogError> {
        Err(BinlogError::ConnectError(
            "TLS support is unavailable because no TLS feature is enabled".into(),
        ))
    }

    pub async fn close(&mut self) -> Result<(), BinlogError> {
        // 超时兜底：对端无响应时 shutdown 永久挂起会让调用方（重连路径）
        // 整体卡死。超时返回错误，由调用方放弃本连接走重连。
        match timeout(CLOSE_TIMEOUT, self.close_inner()).await {
            Ok(res) => res,
            Err(_) => Err(BinlogError::ConnectError(format!(
                "close timed out after {:?} (peer unresponsive), giving up",
                CLOSE_TIMEOUT
            ))),
        }
    }

    async fn close_inner(&mut self) -> Result<(), BinlogError> {
        match self.stream.as_mut() {
            Some(ChannelStream::Plain(stream)) => {
                stream.shutdown().await?;
            }
            #[cfg(feature = "rustls")]
            Some(ChannelStream::TlsRustls(stream)) => {
                stream.shutdown().await?;
            }
            #[cfg(feature = "openssl-tls")]
            Some(ChannelStream::TlsOpenSsl(stream)) => {
                stream.get_mut().shutdown().await?;
            }
            None => {}
        }
        Ok(())
    }

    pub async fn write(&mut self, buf: &[u8], sequence: u8) -> Result<(), BinlogError> {
        let mut wtr = Vec::new();
        wtr.write_u24::<LittleEndian>(buf.len() as u32)?;
        WriteBytesExt::write_u8(&mut wtr, sequence)?;
        Write::write(&mut wtr, buf)?;
        self.write_all(&wtr).await?;
        Ok(())
    }

    async fn read_packet_info(&mut self) -> Result<(usize, u8), BinlogError> {
        let mut buf = vec![0u8; 4];
        match timeout(
            Duration::from_secs(self.timeout_secs),
            self.read_exact_into(&mut buf),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(BinlogError::UnexpectedData(format!(
                    "Read binlog header timeout after {}s while waiting for packet header",
                    self.timeout_secs
                )));
            }
        }
        let mut rdr = Cursor::new(buf);
        let length = rdr.read_u24::<LittleEndian>()? as usize;
        let sequence = ReadBytesExt::read_u8(&mut rdr)?;
        Ok((length, sequence))
    }

    pub async fn read_with_sequece(&mut self) -> Result<(Vec<u8>, u8), BinlogError> {
        let (length, sequence) = self.read_packet_info().await?;
        let buf = if length == MAX_PACKET_LENGTH {
            let mut all_buf = self.read_exact(length).await?;
            loop {
                let (chunk_length, _) = self.read_packet_info().await?;
                let mut chunk_buf = self.read_exact(chunk_length).await?;
                all_buf.append(&mut chunk_buf);
                if chunk_length != MAX_PACKET_LENGTH {
                    break;
                }
            }
            trace!("Received big binlog data, full length: {}", all_buf.len());
            all_buf
        } else {
            self.read_exact(length).await?
        };
        Ok((buf, sequence))
    }

    pub async fn read(&mut self) -> Result<Vec<u8>, BinlogError> {
        let (buf, _sequence) = Self::read_with_sequece(self).await?;
        Ok(buf)
    }

    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, BinlogError> {
        let mut buf = vec![0u8; length];
        self.read_loop(&mut buf).await?;
        Ok(buf)
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> Result<(), BinlogError> {
        self.read_loop(buf).await
    }

    async fn read_loop(&mut self, buf: &mut [u8]) -> Result<(), BinlogError> {
        let length = buf.len();
        let wait_data_millis = 10;
        let max_zero_reads = std::cmp::min(self.timeout_secs * 1000 / wait_data_millis, 300);
        let mut read_count = 0;
        let mut zero_reads = 0;

        while read_count < length {
            match timeout(
                Duration::from_secs(self.timeout_secs),
                self.read_once(&mut buf[read_count..]),
            )
            .await
            {
                Ok(Ok(n)) => {
                    if n == 0 {
                        zero_reads += 1;
                        if zero_reads >= max_zero_reads {
                            return Err(BinlogError::UnexpectedData(format!(
                                "Too many zero-length reads. Expected data length: {}, read so far: {}",
                                length, read_count
                            )));
                        }
                        debug!(
                            "Stream reading binlog returns zero-length data, Expected data length: {}, read so far: {}",
                            length, read_count
                        );
                        tokio::time::sleep(Duration::from_millis(wait_data_millis)).await;
                        continue;
                    }
                    zero_reads = 0;
                    read_count += n;
                    trace!(
                        "Stream reading binlog data, Expected data length: {}, read so far: {}",
                        length,
                        read_count
                    );
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(BinlogError::UnexpectedData(format!(
                        "Read binlog timeout, expect data length: {}, read so far: {}",
                        length, read_count
                    )));
                }
            }
        }
        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), BinlogError> {
        // 写路径同样存在半开挂起：对端不读导致内核发送缓冲满时，
        // write_all/flush 永久 pending。认证握手与 dump 命令都经由此处，
        // 无超时会让重连建链阶段卡死。超时复用 timeout_secs，与读路径一致。
        let write_timeout = Duration::from_secs(self.timeout_secs);
        let write_err = |_: tokio::time::error::Elapsed| {
            BinlogError::ConnectError(format!(
                "write timed out after {:?} (peer unresponsive)",
                write_timeout
            ))
        };
        match &mut self.stream {
            Some(ChannelStream::Plain(stream)) => {
                timeout(write_timeout, AsyncWriteExt::write_all(stream, buf))
                    .await
                    .map_err(write_err)??;
                timeout(write_timeout, AsyncWriteExt::flush(stream))
                    .await
                    .map_err(write_err)??;
            }
            #[cfg(feature = "rustls")]
            Some(ChannelStream::TlsRustls(stream)) => {
                timeout(
                    write_timeout,
                    AsyncWriteExt::write_all(stream.as_mut(), buf),
                )
                .await
                .map_err(write_err)??;
                timeout(write_timeout, AsyncWriteExt::flush(stream.as_mut()))
                    .await
                    .map_err(write_err)??;
            }
            #[cfg(feature = "openssl-tls")]
            Some(ChannelStream::TlsOpenSsl(stream)) => {
                timeout(
                    write_timeout,
                    AsyncWriteExt::write_all(stream.as_mut(), buf),
                )
                .await
                .map_err(write_err)??;
                timeout(write_timeout, AsyncWriteExt::flush(stream.as_mut()))
                    .await
                    .map_err(write_err)??;
            }
            None => {
                return Err(BinlogError::ConnectError(
                    "channel stream is unavailable".into(),
                ))
            }
        }
        Ok(())
    }

    async fn read_once(&mut self, buf: &mut [u8]) -> Result<usize, BinlogError> {
        let read = match self.stream.as_mut() {
            Some(ChannelStream::Plain(stream)) => AsyncReadExt::read(stream, buf).await?,
            #[cfg(feature = "rustls")]
            Some(ChannelStream::TlsRustls(stream)) => {
                AsyncReadExt::read(stream.as_mut(), buf).await?
            }
            #[cfg(feature = "openssl-tls")]
            Some(ChannelStream::TlsOpenSsl(stream)) => {
                AsyncReadExt::read(stream.as_mut(), buf).await?
            }
            None => {
                return Err(BinlogError::ConnectError(
                    "channel stream is unavailable".into(),
                ))
            }
        };
        Ok(read)
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// F3 回归：正常连接上 close 应在 CLOSE_TIMEOUT 内成功返回（行为不回归）。
    #[tokio::test]
    async fn close_on_healthy_connection_succeeds_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _conn = listener.accept().await.unwrap();
            // hold 住连接，保持对端存活
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut channel = PacketChannel::new_for_test(stream, 3);
        let start = std::time::Instant::now();
        channel.close().await.expect("healthy close should succeed");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "healthy close should return immediately"
        );
        server.abort();
    }

    /// F2 回归：对端不读（内核发送缓冲耗尽）时 write_all 必须在
    /// timeout_secs 内报错，而不是永久挂起（跳板机半开场景）。
    #[tokio::test]
    async fn write_all_times_out_when_peer_not_reading() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
            // 永远不读：让客户端发送缓冲逐渐耗尽
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut channel = PacketChannel::new_for_test(stream, 1); // 1s 超时
        // 远大于内核发送缓冲的数据量，保证 write_all 会 pending
        let big_buf = vec![0xABu8; 64 * 1024 * 1024];

        let start = std::time::Instant::now();
        let result = channel.write_all(&big_buf).await;
        let elapsed = start.elapsed();

        server.abort();
        let err = result.expect_err("write must fail when peer never reads");
        assert!(
            err.to_string().contains("write timed out"),
            "expect write timeout error, got: {}",
            err
        );
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(10),
            "timeout should fire near 1s, took {:?}",
            elapsed
        );
    }
}

#[cfg(all(test, feature = "rustls"))]
mod tests {
    use rustls::pki_types::ServerName;

    use super::PacketChannel;

    #[test]
    fn build_server_name_accepts_ipv4_literals() {
        let server_name = PacketChannel::build_server_name("127.0.0.1").unwrap();
        assert!(matches!(server_name, ServerName::IpAddress(_)));
    }

    #[test]
    fn build_server_name_accepts_dns_names() {
        let server_name = PacketChannel::build_server_name("mysql.example.com").unwrap();
        assert!(matches!(server_name, ServerName::DnsName(_)));
    }
}
