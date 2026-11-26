//! The SDK configuration identity calls run under.

use std::time::Duration;

use aws_config::{BehaviorVersion, Region, SdkConfig, retry::RetryConfig, timeout::TimeoutConfig};

/// One retry and a three-second ceiling per call, because a Cognito trigger
/// has five seconds in total and an authorizer answer that arrives late is an
/// answer that was refused.
///
/// Loading resolves credentials and region from the environment, so load once
/// and share the result.
pub async fn load() -> SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .retry_config(RetryConfig::standard().with_max_attempts(2))
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(3))
                .connect_timeout(Duration::from_secs(1))
                .build(),
        )
        .load()
        .await
}

/// `config` pointed at the region a pool id names (`us-east-1_AbC` is
/// `us-east-1`), keeping its credentials, transport, retries, timeouts and
/// endpoint. A pool and its directory have one region, which need not be the
/// caller's. An id that names no region leaves `config` as it is.
pub fn in_pool_region(config: &SdkConfig, pool: &str) -> SdkConfig {
    match pool.split_once('_') {
        Some((region, _)) if region.contains('-') => config
            .to_builder()
            .region(Region::new(region.to_owned()))
            .build(),
        _ => config.clone(),
    }
}
