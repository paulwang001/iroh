RUST_LOG=warn nohup ./target/debug/derper   -c ./derper.toml > ./target/D01.log 2>&1 &
sleep 1s
RUST_LOG=warn nohup ./target/debug/derper   -c ./derper2.toml > ./target/D02.log 2>&1 &