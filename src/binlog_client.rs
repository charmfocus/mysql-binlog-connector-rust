use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    binlog_error::BinlogError,
    binlog_parser::BinlogParser,
    binlog_stream::BinlogStream,
    command::{authenticator::Authenticator, command_util::CommandUtil},
    network::packet_channel::KeepAliveConfig,
};

// 重新导出 ReconnectingBinlogStream 供用户使用
pub use crate::reconnecting_stream::ReconnectingBinlogStream;

#[derive(Debug, Clone)]
pub enum StartPosition {
    BinlogPosition(String, u32),
    Gtid(String),
    Latest,
}

/// 重连配置，支持重试次数和指数退避
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// 最大重试次数，None 表示无限重试
    pub max_retries: Option<u64>,
    /// 初始退避时间
    pub initial_backoff: Duration,
    /// 最大退避时间
    pub max_backoff: Duration,
    /// 退避时间倍增因子
    pub multiplier: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_retries: None,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }
}

impl ReconnectConfig {
    /// 根据当前尝试次数计算退避时间
    pub fn backoff_duration(&self, attempt: u64) -> Duration {
        let d = self
            .initial_backoff
            .mul_f64(self.multiplier.powi(attempt as i32));
        d.min(self.max_backoff)
    }

    /// 判断是否应该继续重试
    pub fn should_retry(&self, attempt: u64) -> bool {
        self.max_retries.map_or(true, |max| attempt < max)
    }
}

#[derive(Clone, Default)]
pub struct BinlogClient {
    /// MySQL server connection URL in format "mysql://user:password@host:port"
    pub url: String,
    /// Name of the binlog file to start replication from, e.g. "mysql-bin.000001"
    /// Only used when gtid_enabled is false
    pub binlog_filename: String,
    /// Position in the binlog file to start replication from
    pub binlog_position: u32,
    /// Unique identifier for this replication client
    /// Must be different from other clients connected to the same MySQL server
    pub server_id: u64,
    /// Whether to enable GTID mode for replication
    pub gtid_enabled: bool,
    /// GTID set in format "uuid:1-100,uuid2:1-200"
    /// Only used when gtid_enabled is true
    pub gtid_set: String,
    /// Heartbeat interval in seconds
    /// Server will send a heartbeat event if no binlog events are received within this interval
    /// If heartbeat_interval_secs=0, server won't send heartbeat events
    pub heartbeat_interval_secs: u64,
    /// Network operation timeout in seconds
    /// Maximum wait time for operations like connection establishment and data reading
    /// If timeout_secs=0, the default value(60) will be used
    pub timeout_secs: u64,

    /// TCP keepalive idle time in seconds
    /// The time period after which the first keepalive packet is sent if no data has been exchanged between the two endpoints
    /// If keepalive_idle_secs=0, TCP keepalive will not be enabled
    pub keepalive_idle_secs: u64,
    /// TCP keepalive interval time in seconds
    /// The time period between keepalive packets if the connection is still active
    /// If keepalive_interval_secs=0, TCP keepalive will not be enabled
    pub keepalive_interval_secs: u64,

    /// 重连配置
    pub reconnect_config: ReconnectConfig,
}

const MIN_BINLOG_POSITION: u32 = 4;

impl BinlogClient {
    pub fn new(url: &str, server_id: u64, position: StartPosition) -> Self {
        let mut client = Self {
            url: url.to_string(),
            server_id,
            timeout_secs: 60,
            ..Default::default()
        };
        match position {
            StartPosition::BinlogPosition(binlog_filename, binlog_position) => {
                client.binlog_filename = binlog_filename.to_string();
                client.binlog_position = binlog_position;
            }
            StartPosition::Gtid(gtid_set) => {
                client.gtid_set = gtid_set.to_string();
                client.gtid_enabled = true;
            }
            StartPosition::Latest => {}
        }
        client
    }

    pub fn with_master_heartbeat(self, heartbeat_interval: Duration) -> Self {
        Self {
            heartbeat_interval_secs: heartbeat_interval.as_secs(),
            ..self
        }
    }

    pub fn with_read_timeout(self, timeout: Duration) -> Self {
        Self {
            timeout_secs: timeout.as_secs(),
            ..self
        }
    }

    pub fn with_keepalive(self, keepalive_idle: Duration, keepalive_interval: Duration) -> Self {
        Self {
            keepalive_idle_secs: keepalive_idle.as_secs(),
            keepalive_interval_secs: keepalive_interval.as_secs(),
            ..self
        }
    }

    pub fn with_reconnect(self, config: ReconnectConfig) -> Self {
        Self {
            reconnect_config: config,
            ..self
        }
    }

    pub async fn connect(&mut self) -> Result<BinlogStream, BinlogError> {
        Self::do_connect(self).await
    }

    /// 创建可自动重连的 binlog stream。
    ///
    /// 内部克隆 BinlogClient 用于重连时获取最新 GTID 位点。
    /// 使用示例：
    /// ```ignore
    /// let client = BinlogClient::new(...).with_reconnect(config);
    /// let mut stream = client.connect_with_reconnect().await?;
    /// while let Ok((header, data)) = stream.read().await { ... }
    /// ```
    pub async fn connect_with_reconnect(self) -> Result<ReconnectingBinlogStream, BinlogError> {
        let config = self.reconnect_config.clone();
        // 使用 Arc 共享 client，重连时克隆以获取最新状态
        let client = Arc::new(std::sync::Mutex::new(self));

        let make_connection: Arc<
            dyn Fn() -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<BinlogStream, BinlogError>> + Send>,
                > + Send
                + Sync,
        > = {
            let client = client.clone();
            Arc::new(move || {
                let client = client.clone();
                Box::pin(async move {
                    let mut c = client.lock().unwrap().clone();
                    c.connect().await
                })
            })
        };

        ReconnectingBinlogStream::connect(config, make_connection).await
    }

    async fn do_connect(&self) -> Result<BinlogStream, BinlogError> {
        // init connect
        let timeout_secs = if self.timeout_secs > 0 {
            self.timeout_secs
        } else {
            60
        };
        let mut authenticator =
            Authenticator::new(&self.url, timeout_secs, self.build_keepalive_config())?;
        let mut channel = authenticator.connect().await?;

        let mut gtid_set = self.gtid_set.clone();
        let mut binlog_filename = self.binlog_filename.clone();
        let mut binlog_position = self.binlog_position;

        if self.gtid_enabled {
            if gtid_set.is_empty() {
                let (_, _, fetched_gtid_set) = CommandUtil::fetch_binlog_info(&mut channel).await?;
                gtid_set = fetched_gtid_set;
            }
        } else {
            // fetch binlog info
            if binlog_filename.is_empty() {
                let (fetched_binlog_filename, fetched_binlog_position, _) =
                    CommandUtil::fetch_binlog_info(&mut channel).await?;
                binlog_filename = fetched_binlog_filename;
                binlog_position = fetched_binlog_position;
            }

            if binlog_position < MIN_BINLOG_POSITION {
                binlog_position = MIN_BINLOG_POSITION;
            }
        }

        // fetch binlog checksum
        let binlog_checksum = CommandUtil::fetch_binlog_checksum(&mut channel).await?;

        // setup connection
        CommandUtil::setup_binlog_connection(&mut channel).await?;

        if self.heartbeat_interval_secs > 0 {
            CommandUtil::enable_heartbeat(&mut channel, self.heartbeat_interval_secs).await?;
        }

        // dump binlog
        let mut client_clone = self.clone();
        client_clone.gtid_set = gtid_set;
        client_clone.binlog_filename = binlog_filename;
        client_clone.binlog_position = binlog_position;
        CommandUtil::dump_binlog(&mut channel, &client_clone).await?;

        // list for binlog
        let parser = BinlogParser {
            checksum_length: binlog_checksum.get_length(),
            table_map_event_by_table_id: HashMap::new(),
        };

        Ok(BinlogStream { channel, parser })
    }

    fn build_keepalive_config(&self) -> Option<KeepAliveConfig> {
        if self.keepalive_idle_secs == 0 || self.keepalive_interval_secs == 0 {
            return None;
        }

        Some(KeepAliveConfig {
            keepidle_secs: self.keepalive_idle_secs,
            keepintvl_secs: self.keepalive_interval_secs,
        })
    }
}
