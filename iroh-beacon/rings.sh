RUST_LOG=warn nohup ./target/debug/examples/ring   --name R01 > ./target/r01.log 2>&1 &
sleep 2s
RUST_LOG=warn nohup ./target/debug/examples/ring   --name R02 > ./target/r02.log 2>&1 &
sleep 2s
RUST_LOG=warn nohup ./target/debug/examples/ring   --name R03 > ./target/r03.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R04 > ./target/r04.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R05 > ./target/r05.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R06 > ./target/r06.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R07 > ./target/r07.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R08 > ./target/r08.log 2>&1 &
sleep 2s
RUST_LOG=info nohup ./target/debug/examples/ring   --name R09 > ./target/r09.log 2>&1 &