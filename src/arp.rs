use eui48::MacAddress;
use std::convert::{TryFrom, TryInto};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ArpOp {
    Request,
    Reply,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Arp {
    pub op: ArpOp,
    pub sha: MacAddress,
    pub spa: Ipv4Addr,
    pub tha: MacAddress,
    pub tpa: Ipv4Addr,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ArpError {
    UnsupportedType,
    InvalidArpOp,
    InvalidSha,
    InvalidSpa,
    InvalidTha,
    InvalidTpa,
    BufferTooSmall,
}

impl std::fmt::Display for ArpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArpError::UnsupportedType => write!(f, "Unsupported ARP type (not ethernet/IPv4)"),
            ArpError::InvalidArpOp => write!(f, "Invalid ARP opcode"),
            ArpError::InvalidSha => write!(f, "Invalid ARP sender hardware address"),
            ArpError::InvalidSpa => write!(f, "Invalid ARP sender protocol address"),
            ArpError::InvalidTha => write!(f, "Invalid ARP target hardware address"),
            ArpError::InvalidTpa => write!(f, "Invalid ARP target protocol address"),
            ArpError::BufferTooSmall => write!(f, "Packet buffer too small"),
        }
    }
}

impl std::error::Error for ArpError {}

impl Arp {
    pub fn reply(&self, ha: MacAddress) -> Result<Self, ArpError> {
        if self.op != ArpOp::Request {
            return Err(ArpError::InvalidArpOp);
        }
        Ok(Self {
            op: ArpOp::Reply,
            sha: ha,
            spa: self.tpa,
            tha: self.sha,
            tpa: self.spa,
        })
    }

    pub fn fill<'a, 'b>(&'a self, buf: &'b mut [u8]) -> Result<&'b [u8], ArpError> {
        if buf.len() < 28 {
            return Err(ArpError::BufferTooSmall);
        }
        buf[0..=6].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00]);
        buf[7] = match self.op {
            ArpOp::Request => 1,
            ArpOp::Reply => 2,
        };
        buf[8..=13].copy_from_slice(self.sha.as_bytes());
        buf[14..=17].copy_from_slice(&self.spa.octets());
        buf[18..=23].copy_from_slice(self.tha.as_bytes());
        buf[24..=27].copy_from_slice(&self.tpa.octets());
        Ok(&buf[0..=27])
    }
}

impl TryFrom<&'_ [u8]> for Arp {
    type Error = ArpError;

    fn try_from(pkt: &'_ [u8]) -> Result<Self, Self::Error> {
        if pkt.len() < 28 {
            return Err(ArpError::BufferTooSmall);
        }
        if !pkt.starts_with(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00]) {
            return Err(ArpError::UnsupportedType);
        }
        Ok(Self {
            op: match pkt[7] {
                1 => ArpOp::Request,
                2 => ArpOp::Reply,
                _ => return Err(ArpError::InvalidArpOp),
            },
            sha: MacAddress::from_bytes(&pkt[8..=13]).map_err(|_| ArpError::InvalidSha)?,
            spa: {
                let bytes: [u8; 4] = pkt[14..=17].try_into().map_err(|_| ArpError::InvalidSpa)?;
                bytes.into()
            },
            tha: MacAddress::from_bytes(&pkt[18..=23]).map_err(|_| ArpError::InvalidTha)?,
            tpa: {
                let bytes: [u8; 4] = pkt[24..=27].try_into().map_err(|_| ArpError::InvalidTpa)?;
                bytes.into()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn t1() {
        let request_pkt: [u8; 28] = [
            0x00, 0x01, 0x08, 0x00, 6, 4, 0, 1, // arp header
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 10, 0, 0, 1, // sender
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 2, // target
        ];
        let request: Arp = request_pkt.as_ref().try_into().unwrap();
        assert_eq!(
            request,
            Arp {
                op: ArpOp::Request,
                sha: MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                spa: "10.0.0.1".parse().unwrap(),
                tha: MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                tpa: "10.0.0.2".parse().unwrap(),
            }
        );

        let mut buf = [0u8; 128];
        assert_eq!(request.fill(&mut buf[..]), Ok(&request_pkt[..]));

        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let reply = request.reply(mac).expect("ARP reply");
        assert_eq!(
            reply,
            Arp {
                op: ArpOp::Reply,
                sha: MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                spa: "10.0.0.2".parse().unwrap(),
                tha: MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                tpa: "10.0.0.1".parse().unwrap(),
            }
        );

        let reply_pkt: [u8; 28] = [
            0x00, 0x01, 0x08, 0x00, 6, 4, 0, 2, // arp header
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 10, 0, 0, 2, // sender
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 10, 0, 0, 1, // target
        ];
        assert_eq!(reply.fill(&mut buf[..]), Ok(&reply_pkt[..]));
    }
}
