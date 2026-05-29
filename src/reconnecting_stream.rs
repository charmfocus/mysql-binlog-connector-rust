use log::warn;

use crate::{
    binlog_client::{BinlogClient, ReconnectConfig},
    binlog_error::BinlogError,
    binlog_stream::BinlogStream,
    command::gtid_set::GtidSet,
    event::{event_data::EventData, event_header::EventHeader},
};

/// Auto-reconnecting binlog stream with built-in GTID tracking.
///
/// Tracks GTID from binlog events internally (like go-mysql's masterInfo).
/// On disconnect, reconnects using the latest tracked GTID.
/// The caller never needs to manage GTID manually.
pub struct ReconnectingBinlogStream {
    stream: BinlogStream,
    config: ReconnectConfig,
    client: BinlogClient,
    gtid_set: GtidSet,
    prev_gtid_set: GtidSet,
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
        Ok(Self { stream, config, client, gtid_set, prev_gtid_set })
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

    /// Read the next binlog event with automatic reconnection.
    ///
    /// GTID events are automatically tracked and used for reconnection.
    /// The caller does NOT need to call any `set_gtid()` method.
    pub async fn read(&mut self) -> Result<(EventHeader, EventData), BinlogError> {
        loop {
            match self.stream.read().await {
                Ok((header, data)) => {
                    // ── Auto-track GTID from GTID events ──
                    // Matches go-mysql's behavior: GTID set updated from binlog events
                    if let EventData::Gtid(ref event) = &data {
                        self.prev_gtid_set = self.gtid_set.clone();
                        if let Err(e) = self.gtid_set.add(&event.gtid) {
                            warn!("[GTID] failed to add GTID {}: {}", event.gtid, e);
                        }
                        self.client.gtid_set = self.gtid_set.to_string();
                    }
                    return Ok((header, data));
                }
                Err(e) => {
                    warn!("[RECONNECT] entered reconnect path, error: {:?}", e);
                    let _ = self.stream.close().await;
                    self.stream = match Self::connect_with_retry(&self.config, &self.client, true).await {
                        Ok(stream) => stream,
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
