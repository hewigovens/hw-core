#[cfg(target_os = "android")]
mod android;
mod logging;

pub(crate) use logging::init_platform_tracing_once;
