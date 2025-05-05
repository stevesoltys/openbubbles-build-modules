cargo build --release
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./target/release/macos-validation-data
