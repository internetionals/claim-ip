use eui48::MacAddress;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{
    recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockAddr, SockFlag, SockType,
};
use std::convert::TryFrom;
use structopt::StructOpt;

pub mod arp;

fn lookup_link_addr(iface: &str) -> Result<LinkAddr, Box<dyn std::error::Error>> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name == iface {
            if let Some(SockAddr::Link(link_addr)) = ifaddr.address {
                return Ok(link_addr);
            }
        }
    }
    Err("interface not found".into())
}

extern "C" fn signal_termination_handler(signo: nix::libc::c_int) {
    log::info!("Terminating due to signal {}", signo);
    std::process::exit(0);
}

#[derive(StructOpt)]
#[structopt(about)]
struct Opt {
    #[structopt(help = "Send ARP announcement (gratuitous ARP) on start", short, long)]
    announce: bool,
    #[structopt(help = "Network interface on which to claim the IP")]
    iface: String,
    #[structopt(help = "IP address to claim")]
    ip: std::net::Ipv4Addr,
    #[structopt(
        help = "MAC address to use when claiming the IP address (defaults to the MAC address of the interface)"
    )]
    mac: Option<MacAddress>,
}

fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    {
        // Explicitly set terminate on signals in case we're running as PID 1 in a container
        use nix::sys::signal::{signal, SigHandler, Signal};
        for signo in [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGQUIT,
        ]
        .iter()
        {
            if let Err(err) =
                unsafe { signal(*signo, SigHandler::Handler(signal_termination_handler)) }
            {
                log::error!("Failed to set signal handler for {}: {}", signo, err);
            }
        }
    }

    // Lookup interface and it's corresponding MAC-address
    let ifaddr = lookup_link_addr(&opt.iface).expect("failed to lookup link address");
    let ifindex = ifaddr.ifindex();
    let mac = opt.mac.unwrap_or_else(|| MacAddress::new(ifaddr.addr()));
    log::info!(
        "Claiming IP {} on {}[{}] for {}",
        opt.ip,
        opt.iface,
        ifindex,
        mac
    );

    // Open a raw socket for sending and receiving ARP packets
    let socket = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .expect("failed to create packet socket");
    {
        let mut bind_addr = ifaddr;
        bind_addr.0.sll_protocol = (nix::libc::ETH_P_ARP as u16).to_be();
        nix::sys::socket::bind(socket, &SockAddr::Link(bind_addr))
            .expect("failed to bind to interface for arp data");
    }

    // Main loop
    let mut rbuf = [0u8; 500];
    let mut wbuf = [0u8; 500];
    if opt.announce {
        let bcast_mac = MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut bcast_lladdr = ifaddr;
        bcast_lladdr.0.sll_addr = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];
        let garp = arp::Arp {
            op: arp::ArpOp::Reply,
            sha: mac,
            spa: opt.ip,
            tha: bcast_mac,
            tpa: opt.ip,
        };
        log::debug!("sending gratuitous arp");
        if let Err(err) = sendto(
            socket,
            garp.fill(&mut wbuf)
                .expect("failed to construct reply packet"),
            &SockAddr::Link(bcast_lladdr),
            MsgFlags::MSG_DONTWAIT,
        ) {
            log::error!("failed to send gratuitous arp: {}", err);
        }
    }
    loop {
        // Receive an ARP packet
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
        let from_mac = MacAddress::new(from.addr());
        log::trace!("received packet from {}: {:x?}", from_mac, pkt);

        // Try to decode the ARP packet
        match arp::Arp::try_from(pkt) {
            // Process ARP requests
            Ok(req) if req.op == arp::ArpOp::Request => {
                log::trace!("received arp request: {:x?}", req);
                if from_mac != req.sha {
                    log::warn!(
                        "received arp with sender mac {} from mac {}",
                        from_mac,
                        req.sha
                    );
                }

                // Reply to ARP requests for the specified IP address
                if req.tpa == opt.ip {
                    log::debug!("sending arp reply");
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

            // Ignore other ARP packets
            Ok(_) => {}

            // Report ARP packet decoding errors
            Err(_) => {
                log::warn!("failed to decode arp packet");
            }
        }
    }
}
