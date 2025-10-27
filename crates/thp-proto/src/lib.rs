pub mod hw {
    pub mod trezor {
        pub mod messages {
            pub mod thp {
                include!(concat!(env!("OUT_DIR"), "/hw.trezor.messages.thp.rs"));
            }
        }
    }
}
