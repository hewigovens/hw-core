#[cfg(all(any(target_os = "android", target_vendor = "apple"), debug_assertions))]
const DEFAULT_TRACING_DIRECTIVES: &str =
    "info,hw_ffi=debug,hw_wallet=debug,trezor_connect=debug,trezor_thp=debug,ble_transport=debug";

#[cfg(all(any(target_os = "android", target_vendor = "apple"), debug_assertions))]
fn default_tracing_filter() -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;

    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_TRACING_DIRECTIVES))
}

// `try_init` also installs the `log` bridge, so `trezor-thp` records reach these subscribers.
#[cfg(all(target_os = "android", debug_assertions))]
fn init_android_tracing_once() {
    use std::sync::Once;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = default_tracing_filter();
        match tracing_android::layer("hwcore-rs") {
            Ok(android_layer) => {
                let _ = tracing_subscriber::registry()
                    .with(filter)
                    .with(android_layer)
                    .try_init();
            }
            Err(_) => {
                let _ = tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .with_ansi(false)
                            .with_target(true)
                            .without_time(),
                    )
                    .try_init();
            }
        }
    });
}

#[cfg(all(target_vendor = "apple", debug_assertions))]
fn init_apple_tracing_once() {
    use std::sync::Once;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::registry()
            .with(default_tracing_filter())
            .with(
                fmt::layer()
                    .with_ansi(false)
                    .with_target(true)
                    .with_writer(std::io::stderr),
            )
            .try_init();
    });
}

pub(crate) fn init_platform_tracing_once() {
    #[cfg(all(target_os = "android", debug_assertions))]
    init_android_tracing_once();
    #[cfg(all(target_vendor = "apple", debug_assertions))]
    init_apple_tracing_once();
}

#[cfg(all(test, target_vendor = "apple", debug_assertions))]
mod tests {
    #[test]
    fn platform_tracing_routes_trezor_thp_log_records_at_debug() {
        super::init_platform_tracing_once();

        assert!(log::log_enabled!(target: "trezor_thp::channel::host", log::Level::Debug));
        assert!(!log::log_enabled!(target: "trezor_thp::channel::host", log::Level::Trace));
        assert!(!log::log_enabled!(target: "unrelated_crate", log::Level::Debug));
    }
}
