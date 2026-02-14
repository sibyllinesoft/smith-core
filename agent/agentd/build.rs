fn main() {
    #[cfg(feature = "grpc")]
    {
        let proto_file = "proto/agentd.proto";

        // Recompile if proto file changes
        println!("cargo:rerun-if-changed={}", proto_file);

        tonic_build::configure()
            .build_server(true)
            .build_client(true)
            .compile_protos(&[proto_file], &["proto"])
            .expect("Failed to compile proto files");
    }
}
