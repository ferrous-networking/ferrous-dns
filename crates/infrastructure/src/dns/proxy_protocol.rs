use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const FIXED_HEADER_LEN: usize = 16;
const MAX_ADDITIONAL_LEN: usize = 536;

const COMMAND_LOCAL: u8 = 0x00;
const COMMAND_PROXY: u8 = 0x01;

const FAMILY_UNSPEC: u8 = 0x00;
const FAMILY_TCP4: u8 = 0x11;
const FAMILY_TCP6: u8 = 0x21;

#[derive(Debug)]
pub enum ProxyProtocolError {
    Io(io::Error),
    InvalidSignature,
    InvalidVersion,
    UnknownCommand,
    AdditionalLenTooLarge,
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error reading PROXY Protocol v2 header: {e}"),
            Self::InvalidSignature => write!(f, "invalid PROXY Protocol v2 signature"),
            Self::InvalidVersion => write!(f, "unsupported PROXY Protocol version (expected 2)"),
            Self::UnknownCommand => write!(f, "unknown PROXY Protocol v2 command nibble"),
            Self::AdditionalLenTooLarge => {
                write!(
                    f,
                    "PROXY Protocol v2 additional length exceeds {MAX_ADDITIONAL_LEN}"
                )
            }
        }
    }
}

impl From<io::Error> for ProxyProtocolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub async fn read_proxy_v2_client_ip<R: AsyncRead + Unpin>(
    stream: &mut R,
    peer_addr: IpAddr,
) -> Result<IpAddr, ProxyProtocolError> {
    let mut header = [0u8; FIXED_HEADER_LEN];
    stream.read_exact(&mut header).await?;

    if header[0..12] != PROXY_V2_SIGNATURE {
        return Err(ProxyProtocolError::InvalidSignature);
    }

    let version = header[12] >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::InvalidVersion);
    }

    let command = header[12] & 0x0F;
    let family = header[13];
    let additional_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    if additional_len > MAX_ADDITIONAL_LEN {
        return Err(ProxyProtocolError::AdditionalLenTooLarge);
    }

    let mut additional = [0u8; MAX_ADDITIONAL_LEN];
    if additional_len > 0 {
        stream.read_exact(&mut additional[..additional_len]).await?;
    }

    match command {
        COMMAND_LOCAL => Ok(peer_addr),
        COMMAND_PROXY => extract_source_ip(family, &additional[..additional_len], peer_addr),
        _ => Err(ProxyProtocolError::UnknownCommand),
    }
}

fn extract_source_ip(
    family: u8,
    additional: &[u8],
    peer_addr: IpAddr,
) -> Result<IpAddr, ProxyProtocolError> {
    match family {
        FAMILY_TCP4 if additional.len() >= 4 => {
            let octets = [additional[0], additional[1], additional[2], additional[3]];
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        FAMILY_TCP6 if additional.len() >= 16 => {
            let octets = [
                additional[0],
                additional[1],
                additional[2],
                additional[3],
                additional[4],
                additional[5],
                additional[6],
                additional[7],
                additional[8],
                additional[9],
                additional[10],
                additional[11],
                additional[12],
                additional[13],
                additional[14],
                additional[15],
            ];
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        FAMILY_UNSPEC => Ok(peer_addr),
        _ => Ok(peer_addr),
    }
}
