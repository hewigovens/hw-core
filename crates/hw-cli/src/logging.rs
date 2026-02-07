use tracing::level_filters::LevelFilter;

pub fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(true)
        .with_thread_names(false)
        .with_thread_ids(false)
        .compact()
        .try_init();
}
