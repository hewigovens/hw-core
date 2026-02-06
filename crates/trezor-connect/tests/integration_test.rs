#[cfg(feature = "ble")]
mod tests {
    use thp_core::Link;
    use trezor_connect::link::BleThpLink;

    // This test just verifies that BleThpLink implements Link and compiles.
    // Real integration testing would require a mock BleLink which is hard to construct
    // without a real device or extensive mocking of btleplug.
    #[test]
    fn test_ble_thp_link_implements_link() {
        fn assert_link<T: Link>() {}
        assert_link::<BleThpLink>();
    }
}
