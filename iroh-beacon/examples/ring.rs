use std::sync::Arc;

use anyhow::{bail, Context};
use clap::Parser;
use iroh_beacon::derp::{default_derp_map, parse_secret_key};
use iroh_beacon::{BeaconRequest, BeaconResponse, Message, SignedMessage, Ticket, BEACON_ALPN};

use iroh_gossip::proto::util::base32;
use iroh_gossip::proto::TopicId;
use iroh_net::{
    derp::{DerpMap, DerpMode, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    key::{PublicKey, SecretKey},
    magic_endpoint::accept_conn,
    MagicEndpoint, NodeAddr,
};
use once_cell::sync::OnceCell;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tracing::{error, info, trace, warn};

pub const RING_ALPN: &[u8] = b"/ring/0";
/// beacon node
#[derive(Parser, Debug)]
struct Args {
    /// secret key to derive our peer id from.
    #[clap(long)]
    secret_key: Option<String>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(
        long,
        default_value = "xxe2y5dilfr6rxubk5bpbynhwjdkw6iqdmagrcueeslqhdkrcn7aeib4tgjzykpyxj2l7idtqzar2qyabuahzqnhexselxerfosi43dcteaqeabamwooemkrj6a2delskpdhqwudcn7ulyrezjrcd4vcnuk4ty6q4flacaqa"
    )]
    boots: Option<String>,
    #[clap(short, long)]
    name: Option<String>,
    // #[clap(subcommand)]
    // command: Command,
}

// #[derive(Parser, Debug)]
// enum Command {
//     /// Open a chat room for a topic and print a ticket for others to join.
//     ///
//     /// If no topic is provided, a new topic will be created.
//     Open {
//         /// Optionally set the topic id (32 bytes, as base32 string).
//         topic: Option<TopicId>,
//     },
//     /// Join a chat room from a ticket.
//     Join {
//         /// The ticket, as base32 string.
//         ticket: String,
//     },
// }

/// Get the default [`DerpMap`].

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing_subscriber::fmt::fmt().pretty().init();
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // parse or generate our secret key
    let secret_key = match args.secret_key {
        None => SecretKey::generate(),
        Some(key) => parse_secret_key(&key)?,
    };
    warn!("> our secret key: {}", base32::fmt(secret_key.to_bytes()));

    let derp_mode = DerpMode::Custom(default_derp_map());

    // setup a notification to emit once the initial endpoints of our local node are discovered
    let notify = Arc::new(Notify::new());

    // build our magic endpoint
    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key.clone())
        .alpns(vec![BEACON_ALPN.to_vec(), RING_ALPN.to_vec()])
        .derp_mode(derp_mode)
        .on_derp_active(Box::new(move || {
            info!("be called when a connection is made to a DERP server");
        }))
        .on_net_info(Box::new(move |net| {
            info!("net>>>{net:?}");
        }))
        .on_endpoints({
            let notify = notify.clone();
            Box::new(move |endpoints| {
                if endpoints.is_empty() {
                    error!("endpoints is empty!");
                    return;
                }
                info!("endpoints:{endpoints:?}");
                // notify the outer task of the initial endpoint update (later updates are not interesting)
                notify.notify_one();
            })
        })
        .bind(args.bind_port)
        .await?;
    warn!("> our peer id: {}", endpoint.peer_id());

    // wait for a first endpoint update so that we know about our endpoint addresses
    notify.notified().await;

    let my_addr = endpoint.my_addr().await?;

    let (topic, boots) = match args.boots {
        Some(ticket) => {
            let Ticket { topic, peers } = Ticket::from_str(&ticket)?;
            warn!("> joining beacon for topic {topic},peers:{peers:?}");
            (topic, peers)
        }
        None => {
            let topic = TopicId::from_bytes(rand::random());
            warn!("> opening beacon for topic {topic}");
            (topic, vec![])
        }
    };
    let endpoint_t = endpoint.clone();

    tokio::spawn(async move {
        while let Some(conn) = endpoint_t.accept().await {
            tokio::spawn(async move {
                let (peer_id, alpn, conn) = accept_conn(conn).await?;
                match alpn.as_bytes() {
                    RING_ALPN => {
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            while let Ok(Some(buf)) = recv.read_chunk(4096, true).await {
                                send.write_chunk(buf.bytes).await?;
                            }
                            send.finish().await?;
                        }
                    }
                    _ => {
                        error!("alpn UNK");
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    let nexts = Arc::new(RwLock::new(HashMap::<PublicKey, NodeAddr>::new()));
    let nexts_t = nexts.clone();
    let endpoint_t = endpoint.clone();
    let (bad_tx, mut bad_rx) = tokio::sync::mpsc::channel::<PublicKey>(1000);
    tokio::spawn(async move {
        let bad_set = Arc::new(RwLock::new(HashSet::<PublicKey>::new()));
        let bad_set_w = bad_set.clone();
        tokio::spawn(async move {
            while let Some(bad) = bad_rx.recv().await {
                let mut w = bad_set_w.write().await;
                w.insert(bad);
            }
        });
        loop {
            let boots = boots.clone();
            let mut rings = vec![];
            for b in boots {
                if let Ok(conn) = endpoint_t.connect(b.clone(), BEACON_ALPN).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let bads = {
                            let r = bad_set.read().await;
                            r.iter().map(|p| p.clone()).collect::<Vec<_>>()
                        };
                        let req = BeaconRequest::Ring(my_addr.node_id, bads.clone());
                        let req = postcard::to_stdvec(&req)?;
                        send.write_all(&req).await?;
                        send.finish().await?;
                        while let Ok(Some(buf)) = recv.read_chunk(4096, true).await {
                            let rsp: BeaconResponse = postcard::from_bytes(&buf.bytes[..])?;
                            match rsp {
                                BeaconResponse::Ring { nodes } => {
                                    rings.extend_from_slice(&nodes);
                                    for n in nodes {
                                        endpoint_t.add_node_addr(n)?;
                                    }
                                }
                            }
                        }
                        if !rings.is_empty() {
                            if !bads.is_empty() {
                                let mut w = bad_set.write().await;
                                for b in bads {
                                    w.remove(&b);
                                }
                            }

                            break;
                        }
                    }
                    conn.close_reason();
                } else {
                    warn!("connect to boot>{b:?} failed");
                }
            }
            if !rings.is_empty() {
                warn!("found rings:{}", rings.len());
                {
                    let mut x = nexts_t.write().await;
                    x.clear();
                    for r in rings {
                        x.insert(r.node_id, r);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(25)).await;
            } else {
                warn!("not found rings:{}", rings.len());
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        Ok::<_, anyhow::Error>(())
    });
    let (tx, rx) = tokio::sync::broadcast::channel::<String>(10);
    let tx2 = tx.clone();
    tokio::spawn(async move {
        loop {
            let rings = {
                let nexts = nexts.read().await;
                nexts
                    .iter()
                    .map(|(x, r)| (x.clone(), r.clone()))
                    .collect::<Vec<_>>()
            };
            if let Some((k, r)) = rings.first() {
                let derp_region = endpoint.my_derp();
                let addr = NodeAddr::from_parts(k.clone(), derp_region, vec![]);
                let (conn, node_id) = match endpoint.connect(addr, RING_ALPN).await {
                    Ok(conn) => (conn, k.clone()),
                    Err(e) => {
                        error!("connect failed: to first:{r:?}");
                        bad_tx.send(k.clone()).await?;
                        if let Some((k, r)) = rings.last() {
                            let addr = NodeAddr::from_parts(k.clone(), derp_region, vec![]);
                            match endpoint.connect(addr, RING_ALPN).await {
                                Ok(conn) => (conn, k.clone()),
                                Err(e) => {
                                    error!("connect failed: to second:{r:?}");
                                    bad_tx.send(k.clone()).await?;
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    continue;
                                }
                            }
                        } else {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                };
                loop {
                    let rings = {
                        let nexts = nexts.read().await;
                        nexts.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>()
                    };
                    if !rings.contains(&node_id) {
                        conn.close_reason();
                        warn!("next node changed");
                        break;
                    }
                    let mut rx2 = tx.subscribe();
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        tokio::spawn(async move {
                            let mut total = 0;
                            while let Ok(Some(x)) = recv.read_chunk(4096, true).await {
                                total += x.bytes.len();
                            }
                            warn!("recv: {total} Byte");
                        });
                        for x in 1..10u8 {
                            let data = vec![x; 32];
                            // warn!("send: {} Byte", data.len());
                            send.write_chunk(bytes::Bytes::from(data)).await?;
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }

                        while let Ok(x) = rx2.try_recv() {
                            send.write_chunk(bytes::Bytes::from(x.as_bytes().to_vec()))
                                .await?;
                        }
                        send.finish().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        break;
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));
    let name = args.name.unwrap_or_default();
    println!("> type a message and hit enter to ring...");
    while let Some(text) = line_rx.recv().await {
        if text.len() > 1 {
            let text = format!("{name}:{}", text.trim());

            println!("{text}");
            tx2.send(text)?;
        }
    }
    Ok(())
}

fn input_loop(line_tx: tokio::sync::mpsc::Sender<String>) -> anyhow::Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin(); // We get `Stdin` here.
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.clone())?;
        buffer.clear();
    }
}
