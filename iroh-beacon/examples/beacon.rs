use std::sync::Arc;

use anyhow::{bail, Context};
use clap::Parser;
use iroh_beacon::derp::{default_derp_map, parse_secret_key};
use iroh_beacon::{Message, SignedMessage, BEACON_ALPN};
use iroh_gossip::{
    net::{Gossip, GOSSIP_ALPN},
    proto::{util::base32, Event, TopicId},
};
use iroh_net::{
    derp::{DerpMap, DerpMode, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    key::{PublicKey, SecretKey},
    magic_endpoint::accept_conn,
    MagicEndpoint, NodeAddr,
};
use once_cell::sync::OnceCell;
use tokio::sync::Notify;
/// beacon node
#[derive(Parser, Debug)]
struct Args {
    /// secret key to derive our peer id from.
    #[clap(long)]
    secret_key: Option<String>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(short, long)]
    ticket: Option<String>,
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
    println!("> our secret key: {}", base32::fmt(secret_key.to_bytes()));

    let derp_mode = DerpMode::Custom(default_derp_map());

    let gossip_cell: OnceCell<Gossip> = OnceCell::new();
    // setup a notification to emit once the initial endpoints of our local node are discovered
    let notify = Arc::new(Notify::new());

    // build our magic endpoint
    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key.clone())
        .alpns(vec![GOSSIP_ALPN.to_vec(), BEACON_ALPN.to_vec()])
        .derp_mode(derp_mode)
        .on_derp_active(Box::new(move || {
            println!("be called when a connection is made to a DERP server");
        }))
        .on_net_info(Box::new(move |net| {
            println!("net>>>{net:?}");
        }))
        .on_endpoints({
            let gossip_cell = gossip_cell.clone();
            let notify = notify.clone();
            Box::new(move |endpoints| {
                if endpoints.is_empty() {
                    eprintln!("endpoints is empty!");
                    return;
                }
                // send our updated endpoints to the gossip protocol to be sent as NodeAddr to peers
                if let Some(gossip) = gossip_cell.get() {
                    eprintln!("endpoints : {endpoints:?}");
                    gossip.update_endpoints(endpoints).ok();
                }
                // notify the outer task of the initial endpoint update (later updates are not interesting)
                notify.notify_one();
            })
        })
        .bind(args.bind_port)
        .await?;
    println!("> our peer id: {}", endpoint.peer_id());

    // wait for a first endpoint update so that we know about our endpoint addresses
    notify.notified().await;

    let my_addr = endpoint.my_addr().await?;
    // create the gossip protocol
    let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default(), &my_addr.info);
    // insert the gossip handle into the gossip cell to be used in the endpoint callbacks above
    gossip_cell.set(gossip.clone()).unwrap();
    let ticket = args.ticket;

    let go = gossip.clone();

    let (tx, topic) = iroh_beacon::run(endpoint, ticket, gossip).await?;

    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    let line = line_tx.clone();
    let name = args.name.clone().unwrap_or_default();
    tokio::spawn(async move {
        let mut x = 0_u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            x += 1;
            line.send(format!("[{name}]: Hello {x}")).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    tokio::signal::ctrl_c().await?;
    // std::thread::spawn(move || input_loop(line_tx));
    // println!("> type a message and hit enter to broadcast...");
    // while let Some(text) = line_rx.recv().await {
    //     if text.len() > 1 {
    //         let text = format!("{}", text.trim());
    //         let msg = Message::Message { text };
    //         let encoded_message = SignedMessage::sign_and_encode(&secret_key, &msg).unwrap();
    //         go.broadcast(topic, encoded_message).await?;
    //     }
    //     // println!("{text}");
    // }
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
