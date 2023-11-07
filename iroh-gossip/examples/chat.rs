use std::{collections::HashMap, fmt, str::FromStr, sync::Arc};

use anyhow::{bail, Context};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::Signature;
use iroh_gossip::{
    net::{Gossip, GOSSIP_ALPN},
    proto::{util::base32, Event, TopicId},
};
use iroh_net::{
    derp::{DerpMap, DerpMode},
    key::{PublicKey, SecretKey},
    magic_endpoint::accept_conn,
    MagicEndpoint, NodeAddr,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use url::Url;

/// Chat over iroh-gossip
///
/// This broadcasts signed messages over iroh-gossip and verifies signatures
/// on received messages.
///
/// By default a new peer id is created when starting the example. To reuse your identity,
/// set the `--secret-key` flag with the secret key printed on a previous invocation.
///
/// By default, the DERP server run by n0 is used. To use a local DERP server, run
///     cargo run --bin derper --features derper -- --dev
/// in another terminal and then set the `-d http://localhost:3340` flag on this example.
#[derive(Parser, Debug)]
struct Args {
    /// secret key to derive our peer id from.
    #[clap(long)]
    secret_key: Option<String>,
    /// Set a custom DERP server. By default, the DERP server hosted by n0 will be used.
    #[clap(short, long)]
    derp: Option<Url>,
    /// Disable DERP completely.
    #[clap(long)]
    no_derp: bool,
    /// Set your nickname.
    #[clap(short, long)]
    name: Option<String>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(short, long, default_value = "0")]
    region_id: u16,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Open a chat room for a topic and print a ticket for others to join.
    ///
    /// If no topic is provided, a new topic will be created.
    Open {
        /// Optionally set the topic id (32 bytes, as base32 string).
        topic: Option<TopicId>,
    },
    /// Join a chat room from a ticket.
    Join {
        /// The ticket, as base32 string.
        ticket: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // parse the cli command
    let (topic, peers) = match &args.command {
        Command::Open { topic } => {
            let topic = topic.unwrap_or_else(|| TopicId::from_bytes(rand::random()));
            println!("> opening chat room for topic {topic}");
            (topic, vec![])
        }
        Command::Join { ticket } => {
            let Ticket { topic, peers } = Ticket::from_str(ticket)?;
            println!("> joining chat room for topic {topic}");
            (topic, peers)
        }
    };

    // parse or generate our secret key
    let secret_key = match args.secret_key {
        None => SecretKey::generate(),
        Some(key) => parse_secret_key(&key)?,
    };
    println!("> our secret key: {}", base32::fmt(secret_key.to_bytes()));

    // configure our derp map
    let derp_mode = match (args.no_derp, args.derp) {
        (false, None) => DerpMode::Default,
        (false, Some(url)) => DerpMode::Custom(DerpMap::from_url(url, args.region_id)),
        (true, None) => DerpMode::Disabled,
        (true, Some(_)) => bail!("You cannot set --no-derp and --derp at the same time"),
    };
    println!("> using DERP servers: {}", fmt_derp_mode(&derp_mode));

    // init a cell that will hold our gossip handle to be used in endpoint callbacks
    let gossip_cell: OnceCell<Gossip> = OnceCell::new();

    // setup a notification to emit once the initial endpoints of our local node are discovered
    let notify = Arc::new(Notify::new());

    // build our magic endpoint
    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .derp_mode(derp_mode)
        .on_endpoints({
            let gossip_cell = gossip_cell.clone();
            let notify = notify.clone();
            Box::new(move |endpoints| {
                if endpoints.is_empty() {
                    return;
                }
                // send our updated endpoints to the gossip protocol to be sent as NodeAddr to peers
                if let Some(gossip) = gossip_cell.get() {
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

    // print a ticket that includes our own peer id and endpoint addresses
    let ticket = {
        let me = endpoint.my_addr().await?;
        let peers = peers.iter().cloned().chain([me]).collect();
        Ticket { topic, peers }
    };
    println!("> ticket to join us: {ticket}");

    // spawn our endpoint loop that forwards incoming connections to the gossiper
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));

    // join the gossip topic by connecting to known peers, if any
    let peer_ids = peers.iter().map(|p| p.node_id).collect();
    if peers.is_empty() {
        println!("> waiting for peers to join us...");
    } else {
        println!("> trying to connect to {} peers...{peers:?}", peers.len());
        // add the peer addrs from the ticket to our endpoint's addressbook so that they can be dialed
        for peer in peers.into_iter() {
            endpoint.add_peer_addr(peer)?;
        }
    };
    println!("> join..");
    let fut = gossip.join(topic, peer_ids).await?;
    tokio::spawn(async move {
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), fut).await {
            Ok(r) => {
                println!("> join ok:{}!", r.is_ok());
            }
            Err(_e) => {
                println!("> join timeout!");
            }
        }
    });
    println!("> connected!");

    // broadcast our name, if set
    if let Some(name) = args.name {
        let message = Message::AboutMe { name };
        let encoded_message = SignedMessage::sign_and_encode(endpoint.secret_key(), &message)?;
        gossip.broadcast(topic, encoded_message).await?;
    }

    // subscribe and print loop
    tokio::spawn(subscribe_loop(gossip.clone(), topic));

    // spawn an input thread that reads stdin
    // not using tokio here because they recommend this for "technical reasons"
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    // broadcast each line we type
    println!("> type a message and hit enter to broadcast...");
    while let Some(text) = line_rx.recv().await {
        let text = text.trim();
        if text.trim() == "quit" {
            gossip.quit(topic).await?;
            println!("> quit");
            break;
        } else if text.trim() == "join" {
            let ticket = {
                let me = endpoint.my_addr().await?;
                println!("> ticket to join me: {me:?}");
                let peers = vec![me];
                Ticket { topic, peers }
            };
            println!("> ticket to join us: {ticket}");
        } else {
            let message = Message::Message {
                text: format!("{text}"),
            };
            let encoded_message = SignedMessage::sign_and_encode(endpoint.secret_key(), &message)?;
            gossip.broadcast(topic, encoded_message).await?;
            
            println!("> sent: {text}[{}]",text.len());
        }
    }

    Ok(())
}

async fn subscribe_loop(gossip: Gossip, topic: TopicId) -> anyhow::Result<()> {
    // init a peerid -> name hashmap
    let mut names = HashMap::new();
    // get a stream that emits updates on our topic
    let mut stream = gossip.subscribe(topic).await?;
    loop {
        let event = stream.recv().await?;
        if let Event::Received(msg) = event {
            let (from, message) = SignedMessage::verify_and_decode(&msg.content)?;
            match message {
                Message::AboutMe { name } => {
                    names.insert(from, name.clone());
                    println!("> {} is now known as {}", fmt_peer_id(&from), name);
                }
                Message::Message { text } => {
                    let name = names
                        .get(&from)
                        .map_or_else(|| fmt_peer_id(&from), String::to_string);
                    println!("{}: {}", name, text);
                }
            }
        }
    }
}

async fn endpoint_loop(endpoint: MagicEndpoint, gossip: Gossip) {
    while let Some(conn) = endpoint.accept().await {
        let gossip = gossip.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(conn, gossip).await {
                println!("> connection closed: {err}");
            }
        });
    }
}
async fn handle_connection(conn: quinn::Connecting, gossip: Gossip) -> anyhow::Result<()> {
    let (peer_id, alpn, conn) = accept_conn(conn).await?;
    match alpn.as_bytes() {
        GOSSIP_ALPN => gossip
            .handle_connection(conn)
            .await
            .context(format!("connection to {peer_id} with ALPN {alpn} failed"))?,
        _ => println!("> ignoring connection from {peer_id}: unsupported ALPN protocol"),
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

#[derive(Debug, Serialize, Deserialize)]
struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn verify_and_decode(bytes: &[u8]) -> anyhow::Result<(PublicKey, Message)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: &Message) -> anyhow::Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let signed_message = Self {
            from,
            data,
            signature,
        };
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded.into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    AboutMe { name: String },
    Message { text: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    peers: Vec<NodeAddr>,
}
impl Ticket {
    /// Deserializes from bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(Into::into)
    }
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
}

/// Serializes to base32.
impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base32::parse_vec(s)?)
    }
}

// helpers

fn fmt_peer_id(input: &PublicKey) -> String {
    base32::fmt_short(input.as_bytes())
}
fn parse_secret_key(secret: &str) -> anyhow::Result<SecretKey> {
    let bytes: [u8; 32] = base32::parse_array(secret)?;
    Ok(SecretKey::from(bytes))
}

fn fmt_derp_mode(derp_mode: &DerpMode) -> String {
    match derp_mode {
        DerpMode::Disabled => "None".to_string(),
        DerpMode::Default => "Default Derp servers".to_string(),
        DerpMode::Custom(map) => map
            .regions()
            .flat_map(|region| region.nodes.iter().map(|node| node.url.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}
