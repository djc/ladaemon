pub mod agent;
pub mod base64url;
mod delay_queue_task;
pub mod http;
pub mod keys;
pub mod pem;
#[cfg(feature = "redis")]
pub mod redis;
mod rng;
mod time;

use std::{error::Error, future::Future, pin::Pin};

pub use delay_queue_task::DelayQueueTask;
pub use rng::SecureRandom;
pub use time::unix_timestamp;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
