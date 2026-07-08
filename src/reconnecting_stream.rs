use std::time::{Duration, Instant};

use log::warn;

use crate::{
    binlog_client::{BinlogClient, ReconnectConfig},
    binlog_error::BinlogError,
    binlog_stream::BinlogStream,
    command::gtid_set::GtidSet,
    event::{event_data::EventData, event_header::EventHeader},
};

/// 连续重连窗口：在此时间内连续重连次数超过阈值时，延长退避
const RECONNECT_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);
/// 连续重连次数阈值：超过此值触发强力退避
const RECONNECT_BURST_THRESHOLD: u64 = 3;

/// Auto-reconnecting binlog stream with built-in GTID tracking.
///
/// Tracks GTID from binlog events internally (like go-mysql's masterInfo).
/// On disconnect, reconnects using the latest tracked GTID.
/// The caller never needs to manage GTID manually.
///
/// 内置主动探活：如果 stream.read() 在 read_timeout 内无数据返回
///（包括心跳事件），则主动断开并重连，防止 TCP 半开连接假死。
pub struct ReconnectingBinlogStream {
    stream: BinlogStream,
    config: ReconnectConfig,
    client: BinlogClient,
    gtid_set: GtidSet,
    prev_gtid_set: GtidSet,
    /// 连续读超时触发的重连次数（用于退避），成功读到数据后清零
    consecutive_read_timeout_reconnects: u64,
    /// 首次读超时重连的时间戳，用于判断是否在"重连风暴"窗口内
    first_read_timeout_reconnect_at: Option<Instant>,
}

impl ReconnectingBinlogStream {
    /// Create a new auto-reconnecting stream.
    ///
    /// Consumes the `BinlogClient`. GTID tracking starts from the client's
    /// initial `gtid_set` and is auto-updated from binlog GTID events.
    pub async fn connect(client: BinlogClient) -> Result<Self, BinlogError> {
        let config = client.reconnect_config.clone();

        // Build initial GtidSet from the client's starting GTID
        let initial_gtid = client.gtid_set.clone();
        let gtid_set = GtidSet::new(&initial_gtid).unwrap_or_default();

        // Connect with retry
        let stream = Self::connect_with_retry(&config, &client, false).await?;

        let prev_gtid_set = gtid_set.clone();
        Ok(Self {
            stream,
            config,
            client,
            gtid_set,
            prev_gtid_set,
            consecutive_read_timeout_reconnects: 0,
            first_read_timeout_reconnect_at: None,
        })
    }

    async fn connect_with_retry(config: &ReconnectConfig, client: &BinlogClient, is_reconnect: bool) -> Result<BinlogStream, BinlogError> {
        if is_reconnect {
            warn!("[RECONNECT] attempting reconnect, GTID: {}", client.gtid_set);
        }
        let mut attempt: u64 = 0;
        loop {
            match client.clone().connect().await {
                Ok(stream) => {
                    if is_reconnect {
                        warn!("[RECONNECT] reconnected successfully");
                    }
                    return Ok(stream);
                }
                Err(e) => {
                    if !config.should_retry(attempt) { return Err(e); }
                    let backoff = config.backoff_duration(attempt);
                    if attempt == 0 {
                        warn!("connect attempt 0 failed: {}, retrying...", e);
                    } else if is_reconnect {
                        warn!("[RECONNECT] attempt {} failed: {}, retrying in {}s",
                            attempt, e, backoff.as_secs());
                    }
                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                }
            }
        }
    }

    /// 计算读超时触发的重连退避时间。
    /// 在 5 分钟内连续触发超过 3 次时，启动强力退避（60s），防止重连风暴。
    fn read_timeout_backoff(&mut self) -> std::time::Duration {
        let now = Instant::now();

        // 检查是否在重连风暴窗口内
        let in_burst_window = self
            .first_read_timeout_reconnect_at
            .map_or(false, |t| now.duration_since(t) < RECONNECT_WINDOW);

        if in_burst_window {
            self.consecutive_read_timeout_reconnects += 1;
        } else {
            self.consecutive_read_timeout_reconnects = 1;
            self.first_read_timeout_reconnect_at = Some(now);
        }

        if self.consecutive_read_timeout_reconnects > RECONNECT_BURST_THRESHOLD {
            warn!(
                "[HEALTHCHECK] {} consecutive read-timeout reconnects in {}s window, applying max backoff {}s",
                self.consecutive_read_timeout_reconnects,
                RECONNECT_WINDOW.as_secs(),
                self.config.max_backoff.as_secs(),
            );
            self.config.max_backoff
        } else {
            Duration::from_secs(1)
        }
    }

    /// Read the next binlog event with automatic reconnection.
    ///
    /// GTID events are automatically tracked and used for reconnection.
    /// The caller does NOT need to call any `set_gtid()` method.
    ///
    /// 内置两层防御：
    /// 1. stream.read() 自身超时（PacketChannel 60s 超时）
    /// 2. 外层 read_timeout 超时（默认 90s）— 主动探活
    ///    如果 stream.read() 超过 read_timeout 无数据返回
    ///    （包括心跳），则主动关闭旧连接并重连。
    pub async fn read(&mut self) -> Result<(EventHeader, EventData), BinlogError> {
        loop {
            let read_timeout = self.config.read_timeout;
            match tokio::time::timeout(read_timeout, self.stream.read()).await {
                Ok(Ok((header, data))) => {
                    // 成功读到数据，重置读超时重连计数器
                    self.consecutive_read_timeout_reconnects = 0;
                    self.first_read_timeout_reconnect_at = None;

                    // ── Auto-track GTID from GTID events ──
                    if let EventData::Gtid(ref event) = &data {
                        self.prev_gtid_set = self.gtid_set.clone();
                        if let Err(e) = self.gtid_set.add(&event.gtid) {
                            warn!("[GTID] failed to add GTID {}: {}", event.gtid, e);
                        }
                        // prev_gtid_set 是上一个已提交事务的 GTID 集合，直接用即可
                        // 无需等 Xid/Query/XaPrepare 再更新
                        self.client.gtid_set = self.prev_gtid_set.to_string();
                    }
                    return Ok((header, data));
                }
                Ok(Err(e)) => {
                    // stream.read() 自身报错（如 TCP 断连）
                    warn!("[RECONNECT] entered reconnect path, error: {:?}", e);
                    let _ = self.stream.close().await;
                    self.stream = match Self::connect_with_retry(&self.config, &self.client, true).await {
                        Ok(stream) => stream,
                        Err(e) => return Err(e),
                    };
                }
                Err(_elapsed) => {
                    // 外层 read_timeout 超时 — 主动探活触发
                    // stream.read() 超过 read_timeout 无数据返回，说明连接可能已静默死亡
                    let backoff = self.read_timeout_backoff();
                    warn!(
                        "[HEALTHCHECK] stream read timeout after {}s, connection may be silently dead. Forcing reconnect (backoff {}s)...",
                        read_timeout.as_secs(),
                        backoff.as_secs(),
                    );
                    let _ = self.stream.close().await;
                    tokio::time::sleep(backoff).await;
                    self.stream = match Self::connect_with_retry(&self.config, &self.client, true).await {
                        Ok(stream) => {
                            warn!("[HEALTHCHECK] reconnected successfully after read timeout");
                            stream
                        }
                        Err(e) => return Err(e),
                    };
                }
            }
        }
    }

    /// Get the current tracked GTID set (including latest event).
    pub fn latest_gtid(&self) -> String {
        self.gtid_set.to_string()
    }

    /// Get the GTID set before the last GTID event was processed.
    /// Used for at-least-once persistence: save prev_gtid before processing
    /// a new transaction, so crash recovery replays rather than skips.
    pub fn prev_gtid(&self) -> String {
        self.prev_gtid_set.to_string()
    }

    /// Close the underlying connection.
    pub async fn close(&mut self) -> Result<(), BinlogError> {
        self.stream.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binlog_parser::BinlogParser;
    use crate::network::packet_channel::PacketChannel;
    use std::collections::HashMap;

    /// 创建一个用于测试的 ReconnectingBinlogStream（使用本地回环 TCP 连接）。
    /// 所有字段使用测试友好的默认值，`read_timeout_backoff()` 不依赖 stream 字段。
    fn new_test_stream(config: ReconnectConfig) -> ReconnectingBinlogStream {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_handle = tokio::task::spawn(async move {
                let _ = listener.accept().await;
            });
            let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            server_handle.await.unwrap();

            let channel = PacketChannel::new_for_test(client_stream, 60);
            let binlog_stream = BinlogStream {
                channel,
                parser: BinlogParser {
                    checksum_length: 0,
                    table_map_event_by_table_id: HashMap::new(),
                },
            };

            let client = BinlogClient::default();

            ReconnectingBinlogStream {
                stream: binlog_stream,
                config,
                client,
                gtid_set: GtidSet::default(),
                prev_gtid_set: GtidSet::default(),
                consecutive_read_timeout_reconnects: 0,
                first_read_timeout_reconnect_at: None,
            }
        })
    }

    /// 直接设置 read_timeout_backoff 的状态字段（用于测试）
    fn set_backoff_state(
        stream: &mut ReconnectingBinlogStream,
        consecutive: u64,
        first_at: Option<std::time::Instant>,
    ) {
        stream.consecutive_read_timeout_reconnects = consecutive;
        stream.first_read_timeout_reconnect_at = first_at;
    }

    // ── ReconnectConfig 默认值测试 ──

    #[test]
    fn test_reconnect_config_defaults() {
        let config = ReconnectConfig::default();
        assert_eq!(config.max_retries, None, "默认应无限重试");
        assert_eq!(config.initial_backoff, Duration::from_secs(1));
        assert_eq!(config.max_backoff, Duration::from_secs(60));
        assert_eq!(config.multiplier, 2.0);
        assert_eq!(config.read_timeout, Duration::from_secs(90));
    }

    // ── ReconnectConfig::backoff_duration 测试 ──

    #[test]
    fn test_backoff_duration_exponential() {
        let config = ReconnectConfig::default();
        assert_eq!(config.backoff_duration(0), Duration::from_secs(1));
        assert_eq!(config.backoff_duration(1), Duration::from_secs(2));
        assert_eq!(config.backoff_duration(2), Duration::from_secs(4));
        assert_eq!(config.backoff_duration(3), Duration::from_secs(8));
        assert_eq!(config.backoff_duration(6), Duration::from_secs(60)); // capped
        assert_eq!(config.backoff_duration(10), Duration::from_secs(60)); // capped
    }

    #[test]
    fn test_backoff_duration_custom_params() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(30),
            multiplier: 3.0,
            ..ReconnectConfig::default()
        };
        assert_eq!(config.backoff_duration(0), Duration::from_secs(5));
        assert_eq!(config.backoff_duration(1), Duration::from_secs(15));
        assert_eq!(config.backoff_duration(2), Duration::from_secs(30)); // 5*9=45, capped
        assert_eq!(config.backoff_duration(3), Duration::from_secs(30)); // still capped
    }

    #[test]
    fn test_backoff_duration_respects_max() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
            ..ReconnectConfig::default()
        };
        for attempt in 0..10 {
            assert!(config.backoff_duration(attempt) <= Duration::from_secs(10));
        }
    }

    // ── ReconnectConfig::should_retry 测试 ──

    #[test]
    fn test_should_retry_unlimited() {
        let config = ReconnectConfig::default();
        assert!(config.should_retry(0));
        assert!(config.should_retry(100));
        assert!(config.should_retry(1000));
    }

    #[test]
    fn test_should_retry_limited() {
        let config = ReconnectConfig {
            max_retries: Some(3),
            ..ReconnectConfig::default()
        };
        assert!(config.should_retry(0));
        assert!(config.should_retry(1));
        assert!(config.should_retry(2));
        assert!(!config.should_retry(3));
        assert!(!config.should_retry(4));
    }

    #[test]
    fn test_should_retry_zero_retries() {
        let config = ReconnectConfig {
            max_retries: Some(0),
            ..ReconnectConfig::default()
        };
        assert!(!config.should_retry(0));
        assert!(!config.should_retry(1));
    }

    // ── read_timeout_backoff 测试 ──

    #[test]
    fn test_read_timeout_backoff_first_call() {
        let mut stream = new_test_stream(ReconnectConfig::default());
        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(1));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 1);
        assert!(stream.first_read_timeout_reconnect_at.is_some());
    }

    #[test]
    fn test_read_timeout_backoff_within_window_no_burst() {
        let mut stream = new_test_stream(ReconnectConfig::default());
        let now = std::time::Instant::now();

        set_backoff_state(&mut stream, 2, Some(now));

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(1));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 3);
    }

    #[test]
    fn test_read_timeout_backoff_burst_detection() {
        let mut stream = new_test_stream(ReconnectConfig::default());
        let now = std::time::Instant::now();

        set_backoff_state(&mut stream, 3, Some(now));

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(60));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 4);
    }

    #[test]
    fn test_read_timeout_backoff_burst_continues() {
        let mut stream = new_test_stream(ReconnectConfig::default());
        let now = std::time::Instant::now();

        set_backoff_state(&mut stream, 5, Some(now));

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(60));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 6);
    }

    #[test]
    fn test_read_timeout_backoff_window_expired_resets_counter() {
        let mut stream = new_test_stream(ReconnectConfig::default());

        let old_time = std::time::Instant::now() - Duration::from_secs(360);
        set_backoff_state(&mut stream, 3, Some(old_time));

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(1));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 1);
        assert!(stream.first_read_timeout_reconnect_at.unwrap() > old_time);
    }

    #[test]
    fn test_read_timeout_backoff_custom_max_backoff() {
        let config = ReconnectConfig {
            max_backoff: Duration::from_secs(30),
            ..ReconnectConfig::default()
        };
        let mut stream = new_test_stream(config);
        let now = std::time::Instant::now();

        set_backoff_state(&mut stream, 3, Some(now));

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_read_timeout_backoff_reset_after_counter_clear() {
        let mut stream = new_test_stream(ReconnectConfig::default());
        let now = std::time::Instant::now();

        set_backoff_state(&mut stream, 3, Some(now));
        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(60));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 4);

        stream.consecutive_read_timeout_reconnects = 0;
        stream.first_read_timeout_reconnect_at = None;

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(1));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 1);
    }

    #[test]
    fn test_read_timeout_backoff_first_at_none() {
        let mut stream = new_test_stream(ReconnectConfig::default());

        stream.first_read_timeout_reconnect_at = None;
        stream.consecutive_read_timeout_reconnects = 0;

        let backoff = stream.read_timeout_backoff();
        assert_eq!(backoff, Duration::from_secs(1));
        assert_eq!(stream.consecutive_read_timeout_reconnects, 1);
        assert!(stream.first_read_timeout_reconnect_at.is_some());
    }

    // ── GTID 追踪测试 ──

    #[test]
    fn test_latest_gtid_initial_state() {
        let stream = new_test_stream(ReconnectConfig::default());
        assert_eq!(stream.latest_gtid(), "");
    }

    #[test]
    fn test_prev_gtid_initial_state() {
        let stream = new_test_stream(ReconnectConfig::default());
        assert_eq!(stream.prev_gtid(), "");
    }

    #[test]
    fn test_prev_gtid_equals_gtid_set_initially() {
        let stream = new_test_stream(ReconnectConfig::default());
        assert_eq!(stream.prev_gtid(), stream.latest_gtid());
    }
}
