use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
};

use log::{info, warn};

use crate::{
    binlog_client::ReconnectConfig,
    binlog_error::BinlogError,
    binlog_stream::BinlogStream,
    event::{event_data::EventData, event_header::EventHeader},
};

type ReconnectFuture =
    Pin<Box<dyn Future<Output = Result<BinlogStream, BinlogError>> + Send>>;

/// 可自动重连的 BinlogStream 包装器。
///
/// 当 `read()` 遇到错误时，使用指数退避策略自动重连并恢复读取，
/// 调用方不需要手动管理重连循环。
pub struct ReconnectingBinlogStream {
    stream: BinlogStream,
    config: ReconnectConfig,
    make_connection: Arc<dyn Fn() -> ReconnectFuture + Send + Sync>,
}

impl ReconnectingBinlogStream {
    /// 创建新的可重连 stream，首次连接失败也会按退避策略重试。
    pub async fn connect(
        config: ReconnectConfig,
        make_connection: Arc<dyn Fn() -> ReconnectFuture + Send + Sync>,
    ) -> Result<Self, BinlogError> {
        let stream = Self::connect_with_retry(&config, &make_connection).await?;
        Ok(Self {
            stream,
            config,
            make_connection,
        })
    }

    async fn connect_with_retry(
        config: &ReconnectConfig,
        make_connection: &Arc<dyn Fn() -> ReconnectFuture + Send + Sync>,
    ) -> Result<BinlogStream, BinlogError> {
        let mut attempt: u64 = 0;
        loop {
            match make_connection().await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    if !config.should_retry(attempt) {
                        return Err(e);
                    }
                    let backoff = config.backoff_duration(attempt);
                    warn!(
                        "连接 binlog 失败: {}, 第 {} 次重试, {}秒后重连...",
                        e,
                        attempt + 1,
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                }
            }
        }
    }

    /// 读取下一个 binlog 事件，出错时自动重连。
    ///
    /// 如果重试次数耗尽仍无法恢复，返回最后一次错误。
    pub async fn read(&mut self) -> Result<(EventHeader, EventData), BinlogError> {
        loop {
            match self.stream.read().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("binlog 读取错误: {}, 开始重连...", e);
                    self.stream = match Self::connect_with_retry(
                        &self.config,
                        &self.make_connection,
                    )
                    .await
                    {
                        Ok(stream) => {
                            info!("binlog 重连成功");
                            stream
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    };
                }
            }
        }
    }

    /// 关闭底层连接。
    pub async fn close(&mut self) -> Result<(), BinlogError> {
        self.stream.close().await
    }
}
