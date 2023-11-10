use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use bytes::Bytes;
use conhash::{ConsistentHash, Node};
use ed25519_dalek::Signature;
use iroh_gossip::{
    net::{Gossip, GOSSIP_ALPN},
    proto::{util::base32, Event, TopicId},
};
use iroh_net::{
    key::{PublicKey, SecretKey},
    magic_endpoint::accept_conn,
    MagicEndpoint, NodeAddr,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
pub mod derp;
pub const BEACON_ALPN: &[u8] = b"/beacon/0";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct BeaconNode {
    key: PublicKey,
    rate: u64,
}
impl Node for BeaconNode {
    fn name(&self) -> String {
        base32::fmt(self.key.as_bytes())
    }
}
impl BeaconNode {
    fn new(key: PublicKey) -> BeaconNode {
        BeaconNode { key, rate: 0 }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
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
pub enum Message {
    Ready { node_addr: NodeAddr },
    AboutMe { name: String },
    Message { text: String },
    Election { epoch: u64, phase: ElectionPhase },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ElectionPhase {
    Proposal { epoch: u64, nodes: Vec<PublicKey> },
    Vote { leader: PublicKey, epoch: u64 },
    Commit { leader: PublicKey, epoch: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BeaconRequest {
    Ring(PublicKey, Vec<PublicKey>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BeaconResponse {
    Ring { nodes: Vec<NodeAddr> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub topic: TopicId,
    pub peers: Vec<NodeAddr>,
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

/// run beacon
pub async fn run(
    endpoint: MagicEndpoint,
    boot_ticket: Option<String>,
    gossip: Gossip,
) -> anyhow::Result<(mpsc::Sender<Message>, TopicId)> {
    // let my_addr = endpoint.my_addr().await?;

    let (topic, peers) = match boot_ticket {
        Some(ticket) => {
            let Ticket { topic, peers } = Ticket::from_str(&ticket)?;
            println!("> joining beacon for topic {topic}");
            (topic, peers)
        }
        None => {
            let topic = TopicId::from_bytes(rand::random());
            println!("> opening beacon for topic {topic}");
            (topic, vec![])
        }
    };

    // print a ticket that includes our own peer id and endpoint addresses
    let ticket = {
        let me = endpoint.my_addr().await?;
        let has = peers.iter().cloned().find(|p| p.node_id == me.node_id);
        let peers = match has {
            Some(_) => peers.clone(),
            None => peers.iter().cloned().chain([me]).collect(),
        };
        Ticket { topic, peers }
    };
    println!("> ticket to join beacon: {ticket}");

    // spawn our endpoint loop that forwards incoming connections to the gossiper
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));

    let peer_ids = peers.iter().map(|p| p.node_id).collect::<Vec<_>>();
    if peers.is_empty() {
        println!("> waiting for peers to join us...");
    } else {
        println!("> trying to connect to {} peers...{peers:?}", peers.len());
        // add the peer addrs from the ticket to our endpoint's addressbook so that they can be dialed
        for peer in peers.into_iter() {
            endpoint.add_node_addr(peer)?;
        }
    };
    let mut boots = HashMap::<PublicKey, Option<Vec<u8>>>::new();
    {
        let me = endpoint.my_addr().await?;
        let k = me.node_id;
        let addr = postcard::to_stdvec(&me)?;
        boots.insert(k, Some(addr));
    }
    let boots = Arc::new(tokio::sync::RwLock::new(boots));
    let go = gossip.clone();
    let key = endpoint.secret_key().clone();
    let boots_t = boots.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = subscribe_loop(go.clone(), topic, &key, boots_t.clone()).await {
                eprintln!("sub>>{e:?}");
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }
    });

    println!("> join..");
    let go = gossip.clone();
    let key = endpoint.secret_key().clone();
    let my_addr = endpoint.my_addr().await?;
    tokio::spawn(async move {
        loop {
            let fut = go.join(topic, peer_ids.clone()).await.unwrap();
            match tokio::time::timeout(tokio::time::Duration::from_secs(6), fut).await {
                Ok(r) => {
                    println!("> join ok:{}!", r.is_ok());
                    let message = Message::Ready { node_addr: my_addr };
                    let encoded_message = SignedMessage::sign_and_encode(&key, &message).unwrap();
                    if let Err(e) = go.broadcast(topic, encoded_message).await {
                        eprintln!("go about>>>{e:?}");
                    }
                    break;
                }
                Err(_e) => {
                    println!("> join timeout!");
                }
            }
        }
    });
    println!("> connected!");
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<Message>(1);
    // let tx = line_tx.clone();
    // tokio::spawn(async move { loop {} });
    // broadcast each line we type
    tokio::spawn(async move {
        while let Some(msg) = line_rx.recv().await {
            let encoded_message = SignedMessage::sign_and_encode(endpoint.secret_key(), &msg)?;
            gossip.broadcast(topic, encoded_message).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    Ok((line_tx, topic))
}

async fn subscribe_loop(
    gossip: Gossip,
    topic: TopicId,
    key: &SecretKey,
    boots: Arc<tokio::sync::RwLock<HashMap<PublicKey, Option<Vec<u8>>>>>,
) -> anyhow::Result<()> {
    // init a peerid -> name hashmap
    // get a stream that emits updates on our topic
    let mut stream = gossip.subscribe(topic).await?;
    let mut final_epoch = 0_u64;
    // let members = HashSet::<PublicKey>::new();
    let mut epoch_timer = std::time::Instant::now();
    let mut epoch_nodes = HashMap::<u64, HashMap<PublicKey, usize>>::new();
    loop {
        let event = stream.recv().await?;
        match event {
            Event::Received(msg) => {
                let (from, message) = SignedMessage::verify_and_decode(&msg.content)?;
                match message {
                    Message::AboutMe { name } => {
                        println!("> {} is now known as {}", fmt_peer_id(&from), name);
                    }
                    Message::Ready { node_addr } => {
                        let p = node_addr.node_id;
                        eprintln!(">>>>>Ready: {p:?}");
                        let addr = postcard::to_stdvec(&node_addr)?;
                        {
                            let mut all = boots.write().await;
                            all.insert(p, Some(addr));
                        }
                    }
                    Message::Message { text } => {
                        {
                            let mut all = boots.write().await;
                            if !all.contains_key(&from) {
                                all.insert(from, None);
                            }
                        }
                        if text.trim() == "boot" {
                            let boots = boots.read().await;
                            let peers = boots
                                .iter()
                                .filter_map(|(k, a)| {
                                    a.clone().map(|v| {
                                        let addr: NodeAddr = postcard::from_bytes(&v).unwrap();
                                        NodeAddr::from_parts(k.clone(), addr.derp_region(), vec![])
                                    })
                                })
                                .collect::<Vec<_>>();
                            let ticket = Ticket { topic, peers };
                            println!("boots:{ticket}");
                        }
                        println!("{final_epoch}>> {}", text);
                        if epoch_timer.elapsed().as_millis() > 10 * 1000 {
                            let ret = elect(
                                gossip.clone(),
                                topic,
                                key,
                                boots.clone(),
                                final_epoch + 1,
                                final_epoch,
                            )
                            .await?;
                            if !ret.is_empty() {
                                let mut members = HashMap::new();
                                for n in ret {
                                    members.insert(n, 0);
                                }
                                epoch_nodes.insert(final_epoch + 1, members);
                            }
                            epoch_timer = std::time::Instant::now();
                        }
                    }
                    Message::Election { epoch, phase } => {
                        let d = std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)?;
                        let now = d.as_secs();
                        eprintln!("[{now}]>>>>>Election epoch:{epoch},phase:{phase:?}");
                        if epoch >= final_epoch {
                            match phase {
                                ElectionPhase::Proposal { epoch, nodes } => {
                                    let mut members = HashMap::new();
                                    let mut ch = conhash::ConsistentHash::default();
                                    for n in nodes {
                                        ch.add(&BeaconNode::new(n.clone()), 32);
                                        members.insert(n, 0);
                                        {
                                            let mut all = boots.write().await;
                                            if !all.contains_key(&n) {
                                                all.insert(n, None);
                                            }
                                        }
                                    }
                                    if let Some(n) = ch.get(&epoch.to_be_bytes()) {
                                        if n.key == from {
                                            epoch_timer = std::time::Instant::now();
                                            epoch_nodes.insert(epoch, members);
                                            let message = Message::Election {
                                                epoch,
                                                phase: ElectionPhase::Vote {
                                                    leader: from,
                                                    epoch,
                                                },
                                            };
                                            let encoded_message =
                                                SignedMessage::sign_and_encode(&key, &message)
                                                    .unwrap();
                                            let go = gossip.clone();
                                            tokio::spawn(async move {
                                                tokio::time::sleep(
                                                    std::time::Duration::from_millis(500),
                                                )
                                                .await;
                                                if let Err(e) =
                                                    go.broadcast(topic, encoded_message).await
                                                {
                                                    eprintln!("go vote>>>{e:?}");
                                                }
                                            });
                                        }
                                    }
                                }
                                ElectionPhase::Commit { leader, epoch } => {
                                    if leader == from {
                                        final_epoch = epoch;
                                        epoch_timer = std::time::Instant::now();
                                    }
                                }
                                ElectionPhase::Vote { leader, epoch } => {
                                    if leader != key.public() {
                                        if let Some(members) = epoch_nodes.get_mut(&epoch) {
                                            let mut ch = conhash::ConsistentHash::default();
                                            let mut itr = members.keys().into_iter();
                                            while let Some(k) = itr.next() {
                                                ch.add(&BeaconNode::new(k.clone()), 32);
                                            }
                                            if let Some(n) = ch.get(&epoch.to_be_bytes()) {
                                                if n.key == leader {
                                                    if let Some(m) = members.get_mut(&from) {
                                                        *m = 1;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        if let Some(members) = epoch_nodes.get_mut(&epoch) {
                                            if let Some(m) = members.get_mut(&from) {
                                                *m = 1;
                                            }
                                            let total = members.len() - 1;
                                            let x: usize = members.values().sum();
                                            let r = x as f32 / total as f32;
                                            if r >= 1.0 / 2.0 {
                                                final_epoch = epoch;
                                                epoch_timer = std::time::Instant::now();
                                                let message = Message::Election {
                                                    epoch,
                                                    phase: ElectionPhase::Commit { leader, epoch },
                                                };
                                                let encoded_message =
                                                    SignedMessage::sign_and_encode(&key, &message)
                                                        .unwrap();
                                                let go = gossip.clone();
                                                if let Err(e) =
                                                    go.broadcast(topic, encoded_message).await
                                                {
                                                    eprintln!("go vote>>>{e:?}");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::NeighborUp(p) => {
                // let name = format!("na");
                // let message = Message::AboutMe { name };
                // let encoded_message = SignedMessage::sign_and_encode(&key, &message).unwrap();
                // if let Err(e) = gossip.broadcast(topic, encoded_message).await {
                //     eprintln!("go about>>>{e:?}");
                // }

                eprintln!(">>>>>NeighborUp: {p:?}");
                // let mut all = boots.write().await;
                // all.insert(p, None);
            }
            Event::NeighborDown(p) => {
                eprintln!(">>>>>NeighborDown: {p:?}");
                {
                    let mut all = boots.write().await;
                    all.remove(&p);
                }

                let ret = elect(
                    gossip.clone(),
                    topic,
                    key,
                    boots.clone(),
                    final_epoch + 1,
                    final_epoch,
                )
                .await?;
                if !ret.is_empty() {
                    let mut members = HashMap::new();
                    for n in ret {
                        members.insert(n, 0);
                    }
                    epoch_nodes.insert(final_epoch + 1, members);
                }
            }
        }
    }
}

async fn elect(
    gossip: Gossip,
    topic: TopicId,
    key: &SecretKey,
    boots: Arc<tokio::sync::RwLock<HashMap<PublicKey, Option<Vec<u8>>>>>,
    next_epoch: u64,
    epoch: u64,
) -> anyhow::Result<Vec<PublicKey>> {
    let nodes = {
        let all = boots.read().await;
        all.keys()
            .into_iter()
            .map(|k| BeaconNode::new(k.clone()))
            .collect::<Vec<_>>()
    };
    if nodes.len() < 3 {
        eprintln!("nodes len < 3");
        return Ok(vec![]);
    }
    let mut proposal = false;
    let mut ch = conhash::ConsistentHash::default();
    let mut members = vec![];
    for n in nodes {
        ch.add(&n, 32);
        members.push(n.key);
    }
    let n_key = next_epoch;
    if let Some(n) = ch.get(&n_key.to_be_bytes()) {
        if n.key == key.public() {
            // I'm leader.
            // make a proposal
            //Election vote
            //Collection of votes
            let message = Message::Election {
                epoch,
                phase: ElectionPhase::Proposal {
                    epoch: n_key,
                    nodes: members.clone(),
                },
            };
            proposal = true;
            println!("Proposal");
            let encoded_message = SignedMessage::sign_and_encode(&key, &message).unwrap();
            if let Err(e) = gossip.broadcast(topic, encoded_message).await {
                eprintln!("go elect>>>{e:?}");
                proposal = false;
            }
        }
    }
    let mm = if proposal { members } else { vec![] };
    Ok(mm)
}

async fn endpoint_loop(endpoint: MagicEndpoint, gossip: Gossip) {
    let relay_nodes = Arc::new(RwLock::new(HashSet::<PublicKey>::new()));
    while let Some(conn) = endpoint.accept().await {
        let gossip = gossip.clone();
        let nodes = relay_nodes.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(conn, gossip, nodes).await {
                println!("> connection closed: {err}");
            }
        });
    }
}
async fn handle_connection(
    conn: quinn::Connecting,
    gossip: Gossip,
    relay_peers: Arc<RwLock<HashSet<PublicKey>>>,
) -> anyhow::Result<()> {
    let (peer_id, alpn, conn) = accept_conn(conn).await?;

    match alpn.as_bytes() {
        GOSSIP_ALPN => gossip
            .handle_connection(conn)
            .await
            .context(format!("connection to {peer_id} with ALPN {alpn} failed"))?,
        BEACON_ALPN => {
            let (mut send, mut recv) = conn.accept_bi().await?;
            let req = recv.read_to_end(4096).await.context("recv failed")?;
            {
                let mut peers = relay_peers.write().await;
                peers.insert(peer_id);
            }
            match postcard::from_bytes::<BeaconRequest>(&req)? {
                BeaconRequest::Ring(key, bads) => {
                    println!("relay req:");
                    if !bads.is_empty() {
                        let mut peers = relay_peers.write().await;
                        for b in bads {
                            peers.remove(&b);
                        }
                    }
                    let mut hash = ConsistentHash::new();
                    {
                        let peers = relay_peers.read().await;
                        if peers.len() < 3 {
                            let rsp = BeaconResponse::Ring { nodes: vec![] };
                            let buf = postcard::to_stdvec(&rsp)?;
                            send.write_chunk(bytes::Bytes::from(buf)).await?;
                            send.finish().await?;
                            return Ok(());
                        }
                        peers.iter().for_each(|p| {
                            if p != &key {
                                hash.add(&BeaconNode::new(p.clone()), 32);
                            }
                        });
                    }
                    let mut peers = vec![];
                    let master = { hash.get(key.as_bytes()).cloned() };
                    if let Some(master) = master {
                        peers.push(NodeAddr::from_parts(master.key, None, vec![]));
                        hash.remove(&master);
                        if let Some(second) = hash.get(key.as_bytes()) {
                            peers.push(NodeAddr::from_parts(second.key, None, vec![]));
                        }
                    }
                    let rsp = BeaconResponse::Ring { nodes: peers };
                    let buf = postcard::to_stdvec(&rsp)?;
                    send.write_chunk(bytes::Bytes::from(buf)).await?;
                    send.finish().await?;
                }
            }
        }
        _ => println!("> ignoring connection from {peer_id}: unsupported ALPN protocol"),
    }
    Ok(())
}
