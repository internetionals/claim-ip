use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{
    recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockAddr, SockFlag, SockType,
};
use std::convert::TryFrom;

pub mod arp;
pub mod types;

fn lookup_link_addr(iface: &str) -> Result<LinkAddr, Box<dyn std::error::Error>> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name == iface {
            if let Some(SockAddr::Link(link_addr)) = ifaddr.address {
                return Ok(link_addr);
            }
        }
    }
    Err("interface not found")?
}

fn main() {
    env_logger::init();
    if std::env::args().len() != 3 {
        eprintln!(
            "Usage: {} <iface> <ip>",
            std::env::args()
                .nth(0)
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or(file!())
        );
        std::process::exit(0);
    }

    let iface = std::env::args().nth(1).expect("no interface supplied");
    let ip: std::net::Ipv4Addr = std::env::args()
        .nth(2)
        .expect("no ip supplied")
        .parse()
        .expect("invalid ip");
    let ifaddr = lookup_link_addr(&iface).expect("failed to lookup link address");
    let ifindex = ifaddr.ifindex();
    let mac = ifaddr.addr();
    log::info!(
        "Claiming IP {} on {}[{}] for {:x?}",
        ip, iface, ifindex, mac
    );

    let socket = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .expect("failed to create packet socket");
    {
        let mut bind_addr = ifaddr.clone();
        bind_addr.0.sll_protocol = (nix::libc::ETH_P_ARP as u16).to_be();
        nix::sys::socket::bind(socket, &SockAddr::Link(bind_addr))
            .expect("failed to bind to interface for arp data");
    }
    let mut rbuf = [0u8; 500];
    let mut wbuf = [0u8; 500];
    loop {
        let (size, from) = match recvfrom(socket, &mut rbuf) {
            Ok(r) => r,
            Err(err) => {
                log::error!("failed to receive packet: {}", err);
                std::process::exit(1);
            }
        };

        let pkt = &rbuf[0..size];
        let from = match from {
            Some(SockAddr::Link(from)) => from,
            _ => {
                log::error!("received packet without link address sender: {:?}", from);
                continue;
            }
        };
        log::trace!("received packet from {:?}: {:x?}", from, pkt);

        match arp::Arp::try_from(pkt) {
            Ok(req) if req.op == arp::ArpOp::Request => {
                log::trace!("received arp request: {:x?}", req);
                if from.addr() != req.sha {
                    log::warn!(
                        "received arp with sender mac {:x?} from mac {:x?}",
                        from.addr(),
                        req.sha
                    );
                }

                if req.tpa == ip {
                    log::trace!("sending arp reply");
                    if let Err(err) = sendto(
                        socket,
                        req.reply(mac)
                            .expect("ARP reply")
                            .fill(&mut wbuf)
                            .expect("failed to construct reply packet"),
                        &SockAddr::Link(from),
                        MsgFlags::MSG_DONTWAIT,
                    ) {
                        log::error!("failed to send arp reply: {}", err);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {
                log::warn!("failed to decode arp packet");
            }
        }
    }
}
