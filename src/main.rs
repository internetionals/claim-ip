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
    println!(
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
                eprintln!("failed to receive packet: {}", err);
                std::process::exit(1);
            }
        };

        let pkt = &rbuf[0..size];
        let from = match from {
            Some(SockAddr::Link(from)) => from,
            _ => {
                eprintln!("received packet without link address sender: {:?}", from);
                continue;
            }
        };
        eprintln!("received packet from {:?}: {:x?}", from, pkt);

        match arp::Arp::try_from(pkt) {
            Ok(arp::Arp::Request(req)) => {
                eprintln!("received arp request: {:x?}", req);
                if from.addr() != req.sha {
                    eprintln!(
                        "received arp with sender mac {:x?} from mac {:x?}",
                        from.addr(),
                        req.sha
                    );
                }

                if req.tpa == ip {
                    eprintln!("sending arp reply");
                    if let Err(err) = sendto(
                        socket,
                        req.reply(mac)
                            .fill(&mut wbuf)
                            .expect("failed to construct reply packet"),
                        &SockAddr::Link(from),
                        MsgFlags::MSG_DONTWAIT,
                    ) {
                        eprintln!("failed to send arp reply: {}", err);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {
                eprintln!("failed to decode arp packet");
            }
        }
    }
}
