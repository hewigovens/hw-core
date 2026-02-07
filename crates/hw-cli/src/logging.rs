use tracing_subscriber::EnvFilter;

pub fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    filter = filter
        .add_directive(
            "rustyline=off"
                .parse()
                .expect("hardcoded directive should parse"),
        )
        .add_directive(
            "rustyline::tty=off"
                .parse()
                .expect("hardcoded directive should parse"),
        );

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_names(false)
        .with_thread_ids(false)
        .compact()
        .try_init();
}
