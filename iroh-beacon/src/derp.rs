use iroh_gossip::proto::util::base32;
use iroh_net::{
    derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    key::SecretKey,
};
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
pub fn parse_secret_key(secret: &str) -> anyhow::Result<SecretKey> {
    let bytes: [u8; 32] = base32::parse_array(secret)?;
    Ok(SecretKey::from(bytes))
}
