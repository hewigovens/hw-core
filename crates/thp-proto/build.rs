fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc not found");
    std::env::set_var("PROTOC", protoc);

    let mut config = prost_build::Config::new();
    config.btree_map(["."]);

    config
        .compile_protos(&["proto/messages-thp.proto"], &["proto"])
        .expect("failed to compile THP protos");
}
