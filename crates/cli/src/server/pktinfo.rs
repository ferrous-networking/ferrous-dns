use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use socket2::Socket;
use tokio::net::UdpSocket;

pub fn enable_pktinfo(socket: &Socket) {
    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

pub async fn recv_with_pktinfo(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    loop {
        socket.readable().await?;
        match try_recv_with_pktinfo(socket, buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

fn try_recv_with_pktinfo(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    let fd = socket.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let from = sockaddr_in_to_socket_addr(&src_addr);
    let dst = extract_pktinfo_dst(&cmsg_buf, msg.msg_controllen as usize);

    Ok((n as usize, from, dst))
}

fn extract_pktinfo_dst(cmsg_buf: &[u8], controllen: usize) -> IpAddr {
    let mut ptr = cmsg_buf.as_ptr() as *const libc::cmsghdr;
    let end = unsafe { cmsg_buf.as_ptr().add(controllen) };

    while !ptr.is_null() && (ptr as *const u8) < end {
        let cmsg = unsafe { &*ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_PKTINFO {
            let pktinfo_ptr = unsafe {
                (ptr as *const u8).add(libc::CMSG_LEN(0) as usize) as *const libc::in_pktinfo
            };
            let pktinfo = unsafe { &*pktinfo_ptr };
            let addr = Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr));
            return IpAddr::V4(addr);
        }
        let next_len = unsafe { libc::CMSG_SPACE(cmsg.cmsg_len as u32 - libc::CMSG_LEN(0)) };
        if next_len == 0 {
            break;
        }
        ptr = unsafe { (ptr as *const u8).add(next_len as usize) as *const libc::cmsghdr };
    }

    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

pub async fn send_with_src_ip(
    socket: &UdpSocket,
    buf: &[u8],
    to: SocketAddr,
    src: IpAddr,
) -> io::Result<()> {
    loop {
        socket.writable().await?;
        match try_send_with_src_ip(socket, buf, to, src) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

fn try_send_with_src_ip(
    socket: &UdpSocket,
    buf: &[u8],
    to: SocketAddr,
    src: IpAddr,
) -> io::Result<()> {
    let IpAddr::V4(src_v4) = src else {
        return socket_send_fallback(socket, buf, to);
    };

    let fd = socket.as_raw_fd();
    let dst_addr = socket_addr_to_sockaddr_in(to);

    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(src_v4.octets()),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };

    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
    let mut cmsg_buf = [0u8; 64];

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return socket_send_fallback(socket, buf, to);
        }
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = libc::IP_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
        data.write(pktinfo);
    }

    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn socket_send_fallback(socket: &UdpSocket, buf: &[u8], to: SocketAddr) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let dst_addr = socket_addr_to_sockaddr_in(to);
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sockaddr_in_to_socket_addr(addr: &libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn socket_addr_to_sockaddr_in(addr: SocketAddr) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    if let IpAddr::V4(v4) = addr.ip() {
        sa.sin_addr.s_addr = u32::from_be_bytes(v4.octets()).to_be();
    }
    sa.sin_port = addr.port().to_be();
    sa
}
