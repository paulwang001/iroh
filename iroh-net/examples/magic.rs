use std::net::SocketAddr;

use clap::Parser;
use iroh_net::{
    defaults::TEST_REGION_ID,
    derp::{DerpMap, DerpMode, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    key::SecretKey,
    magic_endpoint::accept_conn,
    MagicEndpoint, NodeAddr,
};
use tracing::{debug, info};
use url::Url;

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    secret: Option<String>,
    #[clap(short, long, default_value = "n0/iroh/examples/magic/0")]
    alpn: String,
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(long, default_value = "3478")]
    stun_port: u16,
    #[clap(short, long)]
    derp_url: Option<Url>,
    #[clap(long)]
    derp_region: Option<u16>,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Listen,
    Connect {
        peer_id: String,
        #[clap(long)]
        addrs: Option<Vec<SocketAddr>>,
        #[clap(long)]
        derp_region: Option<u16>,
    },
}

/// Get the default [`DerpMap`].
pub fn default_derp_map() -> DerpMap {
    DerpMap::from_regions([default_na_derp_region(), default_eu_derp_region()])
        .expect("default regions invalid")
}

/// Get the default [`DerpRegion`] for NA.
pub fn default_na_derp_region() -> DerpRegion {
    // The default NA derper run by number0.
    let default_n0_derp = DerpNode {
        name: "na-default-1".into(),
        region_id: 1,
        url: format!("http://localhost:8443").parse().unwrap(),
        stun_only: false,
        stun_port: 3478,
        ipv4: UseIpv4::TryDns,
        ipv6: UseIpv6::TryDns,
    };
    DerpRegion {
        region_id: 1,
        nodes: vec![default_n0_derp.into()],
        avoid: false,
        region_code: "default-1".into(),
    }
}

/// Get the default [`DerpRegion`] for EU.
pub fn default_eu_derp_region() -> DerpRegion {
    // The default EU derper run by number0.
    let default_n0_derp = DerpNode {
        name: "eu-default-1".into(),
        region_id: 2,
        url: format!("http://localhost:7443").parse().unwrap(),
        stun_only: false,
        stun_port: 4478,
        ipv4: UseIpv4::TryDns,
        ipv6: UseIpv6::TryDns,
    };
    DerpRegion {
        region_id: 2,
        nodes: vec![default_n0_derp.into()],
        avoid: false,
        region_code: "default-2".into(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().pretty().init();
    let args = Cli::parse();
    let secret_key = match args.secret {
        None => {
            let secret_key = SecretKey::generate();
            println!("our secret key: {}", fmt_secret(&secret_key));
            secret_key
        }
        Some(key) => parse_secret(&key)?,
    };
    let derp_region = args.derp_region;
    let stun_port = args.stun_port;
    let derp_mode = match args.derp_url {
        None => DerpMode::Custom(default_derp_map()),
        Some(url) => DerpMode::Custom(DerpMap::default_from_node(
            url,
            stun_port,
            UseIpv4::TryDns,
            UseIpv6::TryDns,
            derp_region.clone().unwrap_or(TEST_REGION_ID),
        )),
    };

    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![args.alpn.to_string().into_bytes()])
        .derp_mode(derp_mode)
        .bind(args.bind_port)
        .await?;

    let me = endpoint.peer_id();
    let local_addr = endpoint.local_addr()?;
    println!("magic socket listening on {local_addr:?}");
    println!("our peer id: {me}");

    match args.command {
        Command::Listen  => {
            while let Some(conn) = endpoint.accept().await {
                let (peer_id, alpn, conn) = accept_conn(conn).await?;
                info!(
                    "new connection from {peer_id} with ALPN {alpn} (coming from {})",
                    conn.remote_address()
                );
                tokio::spawn(async move {
                    let mut x = 0;
                    loop {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        debug!("accepted bi stream, waiting for data...");
                        let mut y = 0;
                        let mut will_exit = false;
                        while let Ok(Some(t)) = recv.read_chunk(512,true).await {
                            let o = t.offset;
                            let len = t.bytes.len();
                            let msg = String::from_utf8(t.bytes.to_vec())?;
                            println!("{x}:{y}> received: {o}:{len} ::{msg}");
                            if len == 4 && msg == "exit" {
                                will_exit = true;
                            }
                            send.write_chunk(t.bytes).await?;
                            y+=1;
                        }
                        send.finish().await?;
                        x+=1;
                        if will_exit  {
                            println!("exit");
                            break;
                        }
                    }

                    Ok::<_, anyhow::Error>(())
                });
            }
        }
        Command::Connect {
            peer_id,
            addrs,
            derp_region,
        } => {
            let t = std::time::Instant::now();
            let addr =
                NodeAddr::from_parts(peer_id.parse()?, derp_region, addrs.unwrap_or_default());
            let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
            let c_t = t.elapsed().as_millis() as u64;
            tracing::warn!("connected:{c_t} ms");
            for x in 1..=10 {
                let (mut send, mut recv) = conn.open_bi().await?;
                tokio::spawn(async move {
                    for y in 1..=32 {
                        let slice = format!("{x}> Chunk here's {me}");
                        let t = bytes::Bytes::copy_from_slice(slice.as_bytes());
                        send.write_chunk(t).await?;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    send.finish().await?;
                    Ok::<_, anyhow::Error>(())
                });
                while let Ok(Some(t)) = recv.read_chunk(512, true).await {
                    let o = t.offset;
                    let len = t.bytes.len();
                    println!("received: {o}:{len}");
                }
            }
            let c_t2 = t.elapsed().as_millis() as u64;
            tracing::warn!("send:{} ms",c_t2 - c_t);
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(format!("exit").as_bytes()).await?;
            send.finish().await?;
        }
    }
    Ok(())
}

fn fmt_secret(secret_key: &SecretKey) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&secret_key.to_bytes());
    text.make_ascii_lowercase();
    text
}
fn parse_secret(secret: &str) -> anyhow::Result<SecretKey> {
    let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
    let key = SecretKey::from(bytes);
    Ok(key)
}
