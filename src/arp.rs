use crate::types::Eui48Addr;
use std::convert::{TryFrom, TryInto};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub struct ArpRequest {
    pub sha: Eui48Addr,
    pub spa: Ipv4Addr,
    pub tha: Eui48Addr,
    pub tpa: Ipv4Addr,
}

impl ArpRequest {
    pub fn new(sha: Eui48Addr, spa: Ipv4Addr, tha: Eui48Addr, tpa: Ipv4Addr) -> Self {
        Self { tha, tpa, sha, spa }
    }

    pub fn reply<'a>(&'a self, ha: Eui48Addr) -> ArpReply {
        ArpReply {
            sha: ha,
            spa: self.tpa,
            tha: self.sha,
            tpa: self.spa,
        }
    }

    pub fn fill<'a, 'b>(&'a self, buf: &'b mut [u8]) -> Option<&'b [u8]> {
        if buf.len() < 28 {
            return None;
        }
        buf[0..=7].copy_from_slice(&[0x08, 0x06, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
        buf[8..=13].copy_from_slice(&self.tha);
        buf[14..=17].copy_from_slice(&self.tpa.octets());
        buf[18..=23].copy_from_slice(&self.sha);
        buf[24..=27].copy_from_slice(&self.tpa.octets());
        Some(&buf[0..=27])
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArpReply {
    pub sha: Eui48Addr,
    pub spa: Ipv4Addr,
    pub tha: Eui48Addr,
    pub tpa: Ipv4Addr,
}

impl ArpReply {
    pub fn new(sha: Eui48Addr, spa: Ipv4Addr, tha: Eui48Addr, tpa: Ipv4Addr) -> Self {
        Self { tha, tpa, sha, spa }
    }

    pub fn fill<'a, 'b>(&'a self, buf: &'b mut [u8]) -> Option<&'b [u8]> {
        if buf.len() < 28 {
            return None;
        }
        buf[0..=7].copy_from_slice(&[0x08, 0x06, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        buf[8..=13].copy_from_slice(&self.tha);
        buf[14..=17].copy_from_slice(&self.tpa.octets());
        buf[18..=23].copy_from_slice(&self.sha);
        buf[24..=27].copy_from_slice(&self.tpa.octets());
        Some(&buf[0..=27])
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Arp {
    Request(ArpRequest),
    Reply(ArpReply),
}

impl TryFrom<&'_ [u8]> for Arp {
    type Error = ();

    fn try_from(pkt: &'_ [u8]) -> Result<Arp, Self::Error> {
        if pkt.len() < 28 {
            return Err(());
        }
        if !pkt.starts_with(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00]) {
            return Err(());
        }
        match pkt[7] {
            1 => Ok(Arp::Request(ArpRequest {
                sha: pkt[8..=13].try_into().unwrap(),
                spa: {
                    let bytes: [u8; 4] = pkt[14..=17].try_into().unwrap();
                    bytes.into()
                },
                tha: pkt[18..=23].try_into().unwrap(),
                tpa: {
                    let bytes: [u8; 4] = pkt[24..=27].try_into().unwrap();
                    bytes.into()
                },
            })),
            2 => Ok(Arp::Reply(ArpReply {
                sha: pkt[8..=13].try_into().unwrap(),
                spa: {
                    let bytes: [u8; 4] = pkt[14..=17].try_into().unwrap();
                    bytes.into()
                },
                tha: pkt[18..=23].try_into().unwrap(),
                tpa: {
                    let bytes: [u8; 4] = pkt[24..=27].try_into().unwrap();
                    bytes.into()
                },
            })),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn t1() {
        let pkt: [u8; 28] = [
            0x00, 0x01, 0x08, 0x00, 6, 4, 0, 1, // arp header
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 10, 0, 0, 1, // sender
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 2, // target
        ];
        let arp: Arp = pkt.as_ref().try_into().unwrap();
        assert_eq!(
            arp,
            Arp::Request(ArpRequest {
                sha: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                spa: "10.0.0.1".parse().unwrap(),
                tha: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                tpa: "10.0.0.2".parse().unwrap(),
            })
        );

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let reply = match arp {
            Arp::Request(r) => r,
            _ => panic!(),
        };
        let reply = reply.reply(mac);
        assert_eq!(
            reply,
            ArpReply {
                sha: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                spa: "10.0.0.2".parse().unwrap(),
                tha: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                tpa: "10.0.0.1".parse().unwrap(),
            }
        );
    }
}
