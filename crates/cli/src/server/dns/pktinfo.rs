use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};

use socket2::Socket;

// ── Batch constants (Linux only) ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(super) const BATCH_SIZE: usize = 64;
#[cfg(target_os = "linux")]
const RECV_BUF_SIZE: usize = 512;
#[cfg(target_os = "linux")]
const CMSG_BUF_SIZE: usize = 128;

// ── IP_PKTINFO setup ─────────────────────────────────────────────────────────

pub fn enable_pktinfo(socket: &Socket) {
    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    // SAFETY: fd is valid for the lifetime of socket; val is a stack-allocated c_int.
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

// ── SO_BUSY_POLL + SO_INCOMING_CPU (Linux only) ──────────────────────────────

/// Sets SO_BUSY_POLL (50µs spin-poll before epoll sleep) and SO_INCOMING_CPU
/// (RFS hint to steer packets to the correct core) on the given socket fd.
///
/// Both options are best-effort hints: the kernel silently ignores them on
/// kernels/drivers that don't support them, so no error is returned.
#[cfg(target_os = "linux")]
pub(super) fn set_udp_perf_opts(fd: RawFd, cpu_id: usize) {
    let busy_poll: libc::c_int = 50; // 50 µs
    let cpu = cpu_id as libc::c_int;
    // SAFETY: fd is valid; both values are stack-allocated c_int.
    // setsockopt failures are intentionally ignored — these are perf hints only.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &busy_poll as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_INCOMING_CPU,
            &cpu as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

// ── RecvBatch — heap-allocated batch recv state (Linux only) ─────────────────

/// Owns all heap storage for one `recvmmsg` call.
///
/// # Invariant
/// The `Vec`s are allocated with their final capacity in `new()` and must
/// **never reallocate** afterwards. `hdrs` contains raw pointers into
/// `recv_bufs`, `cmsg_bufs`, `src_addrs`, and `iovecs` that become dangling
/// if those Vecs reallocate. `rewire()` is the only place that writes those
/// pointers and is called once from `new()`.
#[cfg(target_os = "linux")]
pub(super) struct RecvBatch {
    /// Contiguous receive buffers: slot i occupies [i*RECV_BUF_SIZE .. (i+1)*RECV_BUF_SIZE].
    recv_bufs: Vec<u8>,
    /// Contiguous cmsg buffers: slot i occupies [i*CMSG_BUF_SIZE .. (i+1)*CMSG_BUF_SIZE].
    cmsg_bufs: Vec<u8>,
    src_addrs: Vec<libc::sockaddr_in>,
    iovecs: Vec<libc::iovec>,
    /// The mmsghdr array passed directly to recvmmsg.
    pub hdrs: Vec<libc::mmsghdr>,
}

// SAFETY: RecvBatch owns all heap memory that the raw pointers inside
// `iovecs` and `hdrs` reference. Moving a Vec does not relocate its heap
// buffer — only the fat-pointer metadata moves — so the wired raw pointers
// remain valid after a cross-thread move. RecvBatch is not Clone; exclusive
// access is guaranteed by the worker task that owns it.
#[cfg(target_os = "linux")]
unsafe impl Send for RecvBatch {}

#[cfg(target_os = "linux")]
impl RecvBatch {
    pub(super) fn new(batch_size: usize) -> Self {
        let mut b = Self {
            recv_bufs: vec![0u8; batch_size * RECV_BUF_SIZE],
            cmsg_bufs: vec![0u8; batch_size * CMSG_BUF_SIZE],
            // SAFETY: sockaddr_in / iovec / mmsghdr are C structs; zero-init is correct.
            src_addrs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            iovecs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            hdrs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
        };
        // SAFETY: rewire establishes all internal pointer relationships. The Vecs
        // will not reallocate after this point (no push/extend is ever called).
        unsafe { b.rewire(batch_size) };
        b
    }

    /// Establishes raw pointer relationships between the mmsghdr array and the
    /// backing storage Vecs. Must be called exactly once, immediately after
    /// allocation, before any use of `hdrs`.
    ///
    /// # Safety
    /// All Vecs must be fully allocated with their final capacity and must not
    /// reallocate after this call. The caller (i.e. `new`) is responsible for
    /// this invariant.
    unsafe fn rewire(&mut self, batch_size: usize) {
        for i in 0..batch_size {
            let buf_ptr = self.recv_bufs.as_mut_ptr().add(i * RECV_BUF_SIZE);
            self.iovecs[i] = libc::iovec {
                iov_base: buf_ptr as *mut libc::c_void,
                iov_len: RECV_BUF_SIZE,
            };

            let cmsg_ptr = self.cmsg_bufs.as_mut_ptr().add(i * CMSG_BUF_SIZE);
            let hdr = &mut self.hdrs[i].msg_hdr;
            hdr.msg_name = &mut self.src_addrs[i] as *mut libc::sockaddr_in as *mut libc::c_void;
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            hdr.msg_iov = &mut self.iovecs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_control = cmsg_ptr as *mut libc::c_void;
            hdr.msg_controllen = CMSG_BUF_SIZE as _;
        }
    }

    /// Restores `msg_controllen` to its original size before each `recvmmsg`
    /// call. The kernel shrinks `msg_controllen` to the actual ancillary data
    /// length; without this reset, subsequent calls may fail to deliver pktinfo.
    pub(super) fn reset_controllen(&mut self, batch_size: usize) {
        for i in 0..batch_size {
            self.hdrs[i].msg_hdr.msg_controllen = CMSG_BUF_SIZE as _;
        }
    }

    /// Returns the parsed metadata and payload for slot `i`.
    /// Valid only for indices `0 <= i < n` where `n` was returned by `recv_batch`.
    pub(super) fn get_msg(&self, i: usize) -> ReceivedMsg<'_> {
        let n = self.hdrs[i].msg_len as usize;
        let data = &self.recv_bufs[i * RECV_BUF_SIZE..i * RECV_BUF_SIZE + n];
        let src = sockaddr_in_to_socket_addr(&self.src_addrs[i]);
        let cmsg_slice = &self.cmsg_bufs[i * CMSG_BUF_SIZE..i * CMSG_BUF_SIZE + CMSG_BUF_SIZE];
        #[allow(clippy::unnecessary_cast)]
        let controllen = self.hdrs[i].msg_hdr.msg_controllen as usize;
        let dst_ip = extract_pktinfo_dst(cmsg_slice, controllen);
        ReceivedMsg { data, src, dst_ip }
    }
}

/// Payload and addressing metadata for one received UDP datagram.
#[cfg(target_os = "linux")]
pub(super) struct ReceivedMsg<'a> {
    /// Raw wire bytes of the DNS query.
    pub data: &'a [u8],
    /// Source address of the client.
    pub src: SocketAddr,
    /// Destination IP (our interface) extracted from IP_PKTINFO.
    pub dst_ip: IpAddr,
}

// ── PendingResponse — one fast-path cache-hit response queued for sendmmsg ───

/// A fast-path DNS response ready to be sent via `send_batch`.
/// `wire` is inline (no extra heap allocation per response).
#[cfg(target_os = "linux")]
pub(super) struct PendingResponse {
    /// Wire bytes; only `wire[..len]` is valid.
    pub wire: [u8; 523],
    pub len: usize,
    pub to: SocketAddr,
    pub src_ip: IpAddr,
}

// ── recv_batch — recvmmsg wrapper ────────────────────────────────────────────

/// Receives up to `BATCH_SIZE` UDP datagrams in a single syscall.
///
/// Returns `Ok(n)` where `n > 0` is the number of messages placed in
/// `batch.hdrs[0..n]`. Returns `Err(WouldBlock)` when the socket has no
/// more pending data.
///
/// # Safety contract for callers
/// `batch` must have been constructed by `RecvBatch::new` and not moved or
/// reallocated since. All internal pointers remain valid for the struct's
/// lifetime.
#[cfg(target_os = "linux")]
pub(super) fn recv_batch(fd: RawFd, batch: &mut RecvBatch) -> io::Result<usize> {
    // Restore msg_controllen so the kernel can write IP_PKTINFO again.
    batch.reset_controllen(BATCH_SIZE);

    // SAFETY: fd is a valid non-blocking UDP socket owned by the caller.
    // batch.hdrs points to heap storage wired in RecvBatch::rewire(); the
    // underlying Vecs will not reallocate. MSG_DONTWAIT returns EAGAIN
    // immediately when no data is available. Null timeout means no blocking.
    let n = unsafe {
        libc::recvmmsg(
            fd,
            batch.hdrs.as_mut_ptr(),
            BATCH_SIZE as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };

    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

// ── send_batch — sendmmsg wrapper ────────────────────────────────────────────

/// Sends all responses in `responses` in a single `sendmmsg` syscall,
/// preserving the source IP via `IP_PKTINFO` for each message.
///
/// Partial sends (socket buffer full) silently drop the unsent tail —
/// acceptable for UDP best-effort semantics.
#[cfg(target_os = "linux")]
pub(super) fn send_batch(fd: RawFd, responses: &[PendingResponse]) -> io::Result<()> {
    if responses.is_empty() {
        return Ok(());
    }

    // SAFETY: CMSG_SPACE is a pure size computation; no pointer dereferences.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize };

    let count = responses.len();

    // Per-message ancillary data buffers — one per response, heap-allocated.
    // Total: ~28 bytes × 64 = ~1.8 KB.
    let mut send_cmsg_bufs: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; cmsg_space]).collect();
    let mut dst_addrs: Vec<libc::sockaddr_in> = responses
        .iter()
        .map(|r| socket_addr_to_sockaddr_in(r.to))
        .collect();
    let mut iovecs: Vec<libc::iovec> = responses
        .iter()
        .map(|r| libc::iovec {
            iov_base: r.wire.as_ptr() as *mut libc::c_void,
            iov_len: r.len,
        })
        .collect();

    // SAFETY: All Vecs above are fully allocated with count elements and will
    // not reallocate. hdrs[i].msg_hdr fields point into iovecs[i],
    // dst_addrs[i], and send_cmsg_bufs[i], all of which outlive this function.
    // CMSG_FIRSTHDR / CMSG_DATA follow the POSIX ancillary data protocol.
    let mut hdrs: Vec<libc::mmsghdr> = (0..count)
        .map(|i| {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = &mut dst_addrs[i] as *mut libc::sockaddr_in as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            hdr.msg_hdr.msg_iov = &mut iovecs[i];
            hdr.msg_hdr.msg_iovlen = 1;

            if let IpAddr::V4(src_v4) = responses[i].src_ip {
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(src_v4.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                hdr.msg_hdr.msg_control = send_cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
                hdr.msg_hdr.msg_controllen = cmsg_space as _;

                // SAFETY: msg_control points to a zeroed buffer of cmsg_space
                // bytes. CMSG_FIRSTHDR / CMSG_DATA follow POSIX protocol.
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&hdr.msg_hdr);
                    if !cmsg.is_null() {
                        (*cmsg).cmsg_level = libc::IPPROTO_IP;
                        (*cmsg).cmsg_type = libc::IP_PKTINFO;
                        (*cmsg).cmsg_len =
                            libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;
                        let data = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
                        data.write(pktinfo);
                    }
                }
            }
            // IPv6 src: msg_control stays null; kernel picks the source address.
            hdr
        })
        .collect();

    // SAFETY: fd is a valid non-blocking UDP socket. hdrs[i] is fully
    // initialized above, pointing into iovecs[i], dst_addrs[i], and
    // send_cmsg_bufs[i], all of which remain valid for the duration of this
    // syscall. MSG_DONTWAIT avoids blocking if the send buffer is full.
    let n = unsafe {
        libc::sendmmsg(
            fd,
            hdrs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT as _,
        )
    };

    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── Single-message fallback (non-Linux) ───────────────────────────────────────

#[cfg(not(target_os = "linux"))]
pub(super) fn try_recv_with_pktinfo(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    let fd = socket.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: sockaddr_in and msghdr are C structs; zeroing is the correct way to initialize them.
    let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: fd is valid; msg points to properly initialized iov and cmsg_buf on the stack.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let from = sockaddr_in_to_socket_addr(&src_addr);
    let controllen: usize = msg.msg_controllen as _;
    let dst = extract_pktinfo_dst(&cmsg_buf, controllen);

    Ok((n as usize, from, dst))
}

pub(super) fn try_send_with_src_ip(
    socket: &std::net::UdpSocket,
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

    // SAFETY: CMSG_SPACE is a pure size computation; no pointer dereference.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
    let mut cmsg_buf = [0u8; 64];

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is a C struct; zeroing is the correct initialization before setting fields.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: msg is fully initialized above; CMSG_FIRSTHDR/CMSG_DATA follow POSIX ancillary data protocol.
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

    // SAFETY: fd is valid; msg points to properly initialized iov and cmsg_buf on the stack.
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_pktinfo_dst(cmsg_buf: &[u8], controllen: usize) -> IpAddr {
    let mut ptr = cmsg_buf.as_ptr() as *const libc::cmsghdr;
    // SAFETY: controllen is bounded by cmsg_buf.len() as set in try_recv_with_pktinfo.
    let end = unsafe { cmsg_buf.as_ptr().add(controllen) };

    while !ptr.is_null() && (ptr as *const u8) < end {
        // SAFETY: ptr is within [cmsg_buf, end) which is valid memory from the kernel recvmsg call.
        let cmsg = unsafe { &*ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_PKTINFO {
            // SAFETY: CMSG_LEN(0) is the standard offset to the data payload; in_pktinfo is aligned.
            let pktinfo_ptr = unsafe {
                (ptr as *const u8).add(libc::CMSG_LEN(0) as usize) as *const libc::in_pktinfo
            };
            // SAFETY: kernel wrote a valid in_pktinfo at this location when IP_PKTINFO is set.
            let pktinfo = unsafe { &*pktinfo_ptr };
            let addr = Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr));
            return IpAddr::V4(addr);
        }
        // SAFETY: CMSG_SPACE returns the aligned size; advancing by it keeps ptr within the buffer.
        let next_len = unsafe { libc::CMSG_SPACE(cmsg.cmsg_len as u32 - libc::CMSG_LEN(0)) };
        if next_len == 0 {
            break;
        }
        ptr = unsafe { (ptr as *const u8).add(next_len as usize) as *const libc::cmsghdr };
    }

    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn socket_send_fallback(
    socket: &std::net::UdpSocket,
    buf: &[u8],
    to: SocketAddr,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let dst_addr = socket_addr_to_sockaddr_in(to);
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is a C struct; zeroing is the correct initialization before setting fields.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    // SAFETY: fd is valid; msg points to properly initialized iov on the stack.
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn sockaddr_in_to_socket_addr(addr: &libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

pub(super) fn socket_addr_to_sockaddr_in(addr: SocketAddr) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is a C struct; zeroing is the correct initialization before setting fields.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    if let IpAddr::V4(v4) = addr.ip() {
        sa.sin_addr.s_addr = u32::from_be_bytes(v4.octets()).to_be();
    }
    sa.sin_port = addr.port().to_be();
    sa
}
