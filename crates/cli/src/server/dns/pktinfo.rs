use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};

use socket2::Socket;

// ── Batch constants (Linux only) ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(super) const BATCH_SIZE: usize = 64;
#[cfg(target_os = "linux")]
const RECV_BUF_SIZE: usize = 512;
#[cfg(target_os = "linux")]
const CMSG_BUF_SIZE: usize = 128;

// ── IPV6_PKTINFO setup ───────────────────────────────────────────────────────
//
// The UDP path is unified on AF_INET6 dual-stack sockets (see mod.rs): IPv4
// clients arrive as v4-mapped addresses (`::ffff:a.b.c.d`) and the kernel
// delivers their destination via IPV6_PKTINFO, so only the IPv6 option is set.

pub fn enable_pktinfo(socket: &Socket) {
    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    // SAFETY: fd is valid for the lifetime of socket; val is a stack-allocated c_int.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
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
    src_addrs: Vec<libc::sockaddr_in6>,
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
            // SAFETY: sockaddr_in6 / iovec / mmsghdr are C structs; zero-init is correct.
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
            hdr.msg_name = &mut self.src_addrs[i] as *mut libc::sockaddr_in6 as *mut libc::c_void;
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
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
        let src = sockaddr_in6_to_socket_addr(&self.src_addrs[i]);
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
    /// Source address of the client (v4-mapped clients normalised to `IpAddr::V4`).
    pub src: SocketAddr,
    /// Destination IP (our interface) extracted from IPV6_PKTINFO.
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

/// A fast-path WireData response (MX, TXT, NS, CNAME, SOA, PTR) queued for
/// individual sendmsg. Heap-allocated because WireData can exceed 523 bytes.
#[cfg(target_os = "linux")]
pub(super) struct PendingWireResponse {
    pub data: Vec<u8>,
    pub to: SocketAddr,
    pub src_ip: IpAddr,
}

// ── SendBatch — heap-allocated batch send state (Linux only) ─────────────────

/// Owns all heap storage for one `sendmmsg` call.
///
/// # Invariant
/// The `Vec`s are allocated with their final capacity in `new()` and must
/// **never reallocate** afterwards. `hdrs` contains raw pointers into
/// `cmsg_bufs` and `dst_addrs` that become dangling if those Vecs reallocate.
/// `iovecs[i].iov_base` is set per-call to point into the caller's
/// `PendingResponse.wire`; `dst_addrs[i]` and `cmsg_bufs` are overwritten on
/// each `prepare()` call.
#[cfg(target_os = "linux")]
pub(super) struct SendBatch {
    /// Contiguous cmsg buffers: slot i occupies [i*cmsg_space .. (i+1)*cmsg_space].
    cmsg_bufs: Vec<u8>,
    dst_addrs: Vec<libc::sockaddr_in6>,
    iovecs: Vec<libc::iovec>,
    /// The mmsghdr array passed directly to sendmmsg.
    pub hdrs: Vec<libc::mmsghdr>,
    cmsg_space: usize,
}

// SAFETY: SendBatch owns all heap memory that the raw pointers inside `hdrs`
// reference. Moving a Vec does not relocate its heap buffer, so the wired raw
// pointers into `cmsg_bufs` and `dst_addrs` remain valid after a cross-thread
// move. SendBatch is not Clone; exclusive access is guaranteed by the worker.
#[cfg(target_os = "linux")]
unsafe impl Send for SendBatch {}

#[cfg(target_os = "linux")]
impl SendBatch {
    pub(super) fn new(batch_size: usize) -> Self {
        // SAFETY: CMSG_SPACE is a pure size computation; no pointer dereference.
        let cmsg_space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize };

        let mut b = Self {
            cmsg_bufs: vec![0u8; batch_size * cmsg_space],
            // SAFETY: sockaddr_in6 / iovec / mmsghdr are C structs; zero-init is correct.
            dst_addrs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            iovecs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            hdrs: (0..batch_size)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            cmsg_space,
        };
        // SAFETY: rewire establishes stable pointer relationships into cmsg_bufs
        // and dst_addrs. Those Vecs will not reallocate after this point.
        unsafe { b.rewire(batch_size) };
        b
    }

    /// Wires the stable pointers (msg_name, msg_control) that do not change
    /// between calls. `iov_base` is caller-supplied per response.
    ///
    /// # Safety
    /// All Vecs must be fully allocated with their final capacity and must not
    /// reallocate after this call. The caller (i.e. `new`) is responsible for
    /// this invariant.
    unsafe fn rewire(&mut self, batch_size: usize) {
        for i in 0..batch_size {
            let hdr = &mut self.hdrs[i].msg_hdr;
            hdr.msg_name = &mut self.dst_addrs[i] as *mut libc::sockaddr_in6 as *mut libc::c_void;
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            hdr.msg_iov = &mut self.iovecs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_control =
                self.cmsg_bufs.as_mut_ptr().add(i * self.cmsg_space) as *mut libc::c_void;
            hdr.msg_controllen = self.cmsg_space as _;
        }
    }

    /// Fills in per-message fields (destination, iov, pktinfo) for `responses`
    /// and calls `sendmmsg`. Returns `Ok(())` on success or partial send.
    pub(super) fn send(&mut self, fd: RawFd, responses: &[PendingResponse]) -> io::Result<()> {
        let count = responses.len();
        if count == 0 {
            return Ok(());
        }

        for (i, r) in responses.iter().enumerate() {
            self.dst_addrs[i] = socket_addr_to_sockaddr_in6(r.to);

            self.iovecs[i] = libc::iovec {
                iov_base: r.wire.as_ptr() as *mut libc::c_void,
                iov_len: r.len,
            };

            // Zero out the cmsg slot before writing pktinfo.
            let cmsg_slot = &mut self.cmsg_bufs[i * self.cmsg_space..(i + 1) * self.cmsg_space];
            cmsg_slot.fill(0);

            let hdr = &mut self.hdrs[i].msg_hdr;
            // msg_name, msg_iov, msg_control already wired in rewire().
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            hdr.msg_iovlen = 1;

            if is_unspecified(r.src_ip) {
                // No captured destination: let the kernel pick the source address.
                hdr.msg_controllen = 0;
            } else {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_addr: ip_to_in6_addr(r.src_ip),
                    ipi6_ifindex: dest_scope_id(r.to),
                };
                hdr.msg_controllen = self.cmsg_space as _;

                // SAFETY: msg_control points to a zeroed slot in cmsg_bufs of
                // exactly cmsg_space bytes. CMSG_FIRSTHDR/CMSG_DATA follow POSIX.
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(hdr as *const _);
                    if !cmsg.is_null() {
                        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                        (*cmsg).cmsg_len =
                            libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                        let data = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
                        data.write(pktinfo);
                    }
                }
            }
        }

        // SAFETY: fd is a valid non-blocking UDP socket. hdrs[0..count] are
        // fully populated above; all pointers remain valid for the syscall
        // duration. MSG_DONTWAIT avoids blocking when the send buffer is full.
        let n = unsafe {
            libc::sendmmsg(
                fd,
                self.hdrs.as_mut_ptr(),
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
    // Restore msg_controllen so the kernel can write IPV6_PKTINFO again.
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
    // SAFETY: sockaddr_in6 and msghdr are C structs; zeroing is the correct way to initialize them.
    let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: fd is valid; msg points to properly initialized iov and cmsg_buf on the stack.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let from = sockaddr_in6_to_socket_addr(&src_addr);
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
    if is_unspecified(src) {
        return socket_send_fallback(socket, buf, to);
    }

    let fd = socket.as_raw_fd();
    let dst_addr = socket_addr_to_sockaddr_in6(to);

    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: ip_to_in6_addr(src),
        ipi6_ifindex: dest_scope_id(to),
    };

    // SAFETY: CMSG_SPACE is a pure size computation; no pointer dereference.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) } as usize;
    let mut cmsg_buf = [0u8; 64];

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is a C struct; zeroing is the correct initialization before setting fields.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in6 as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
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
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
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
    // SAFETY: controllen is bounded by cmsg_buf.len() as set by the caller.
    let end = unsafe { cmsg_buf.as_ptr().add(controllen) };

    while !ptr.is_null() && (ptr as *const u8) < end {
        // SAFETY: ptr is within [cmsg_buf, end) which is valid memory from the kernel recvmsg call.
        let cmsg = unsafe { &*ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
            // SAFETY: CMSG_LEN(0) is the standard offset to the data payload; in6_pktinfo is aligned.
            let pktinfo_ptr = unsafe {
                (ptr as *const u8).add(libc::CMSG_LEN(0) as usize) as *const libc::in6_pktinfo
            };
            // SAFETY: kernel wrote a valid in6_pktinfo at this location when IPV6_PKTINFO is set.
            let pktinfo = unsafe { &*pktinfo_ptr };
            let v6 = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
            return unmap_v4(v6);
        }
        // SAFETY: CMSG_SPACE returns the aligned size; advancing by it keeps ptr within the buffer.
        let next_len = unsafe { libc::CMSG_SPACE(cmsg.cmsg_len as u32 - libc::CMSG_LEN(0)) };
        if next_len == 0 {
            break;
        }
        ptr = unsafe { (ptr as *const u8).add(next_len as usize) as *const libc::cmsghdr };
    }

    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

fn socket_send_fallback(
    socket: &std::net::UdpSocket,
    buf: &[u8],
    to: SocketAddr,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let dst_addr = socket_addr_to_sockaddr_in6(to);
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is a C struct; zeroing is the correct initialization before setting fields.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dst_addr as *const libc::sockaddr_in6 as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    // SAFETY: fd is valid; msg points to properly initialized iov on the stack.
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Normalises a (possibly v4-mapped) IPv6 address back to a real `IpAddr::V4`
/// so the application's client-IP / blocking logic still sees genuine IPv4.
fn unmap_v4(v6: Ipv6Addr) -> IpAddr {
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Converts an `IpAddr` to an `in6_addr`, mapping IPv4 to `::ffff:a.b.c.d` so it
/// can be used with the dual-stack AF_INET6 socket.
fn ip_to_in6_addr(ip: IpAddr) -> libc::in6_addr {
    let v6 = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    libc::in6_addr {
        s6_addr: v6.octets(),
    }
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Scope id of a destination address, used as the reply's outgoing interface
/// so link-local clients are answered on the link the query came from.
fn dest_scope_id(addr: SocketAddr) -> u32 {
    match addr {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    }
}

/// Normalises a v4-mapped socket address (`::ffff:a.b.c.d`) back to plain IPv4.
/// The dual-stack listeners report IPv4 peers in mapped form; client-facing
/// logic (groups, limits, logs) expects real IPv4.
pub(super) fn unmap_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Rewrites an IPv4 bind address into its v4-mapped form (`::ffff:a.b.c.d`) so
/// every listener can be created on an AF_INET6 socket. An IPv6 bind is left
/// alone: combined with `set_only_v6(false)`, a `[::]` bind then serves both
/// families on a single socket, while a mapped IPv4 bind stays v4-only.
pub(super) fn v6_mapped_bind_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        SocketAddr::V6(_) => addr,
    }
}

pub(super) fn sockaddr_in6_to_socket_addr(addr: &libc::sockaddr_in6) -> SocketAddr {
    let v6 = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    match unmap_v4(v6) {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
        // Keep the scope id: replies to link-local clients need it.
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, addr.sin6_scope_id)),
    }
}

pub(super) fn socket_addr_to_sockaddr_in6(addr: SocketAddr) -> libc::sockaddr_in6 {
    // SAFETY: sockaddr_in6 is a C struct; zeroing is the correct initialization before setting fields.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr = ip_to_in6_addr(addr.ip());
    sa.sin6_port = addr.port().to_be();
    if let SocketAddr::V6(v6) = addr {
        sa.sin6_scope_id = v6.scope_id();
    }
    sa
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn unmap_v4_returns_real_v4_for_mapped_address() {
        let mapped: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(unmap_v4(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn unmap_v4_keeps_native_v6() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(unmap_v4(v6), IpAddr::V6(v6));
    }

    #[test]
    fn ip_to_in6_addr_maps_v4() {
        let addr = ip_to_in6_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let expected: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(addr.s6_addr, expected.octets());
    }

    #[test]
    fn ip_to_in6_addr_passes_v6_through() {
        let v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(ip_to_in6_addr(IpAddr::V6(v6)).s6_addr, v6.octets());
    }

    #[test]
    fn is_unspecified_detects_both_families() {
        assert!(is_unspecified("0.0.0.0".parse().unwrap()));
        assert!(is_unspecified("::".parse().unwrap()));
        assert!(!is_unspecified("192.0.2.1".parse().unwrap()));
        assert!(!is_unspecified("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn sockaddr_round_trip_v4() {
        let addr: SocketAddr = "192.0.2.1:5353".parse().unwrap();
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sa.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
    }

    #[test]
    fn sockaddr_round_trip_v6() {
        let addr: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
    }

    #[test]
    fn sockaddr_round_trip_keeps_link_local_scope_id() {
        let addr = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7));
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sa.sin6_scope_id, 7);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
        assert_eq!(dest_scope_id(addr), 7);
    }

    #[test]
    fn unmap_socket_addr_normalises_mapped_peers() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:4242".parse().unwrap();
        assert_eq!(
            unmap_socket_addr(mapped),
            "192.0.2.1:4242".parse::<SocketAddr>().unwrap()
        );
        let v6: SocketAddr = "[2001:db8::1]:4242".parse().unwrap();
        assert_eq!(unmap_socket_addr(v6), v6);
    }

    #[test]
    fn v6_mapped_bind_addr_maps_ipv4_binds() {
        let v4: SocketAddr = "192.0.2.1:853".parse().unwrap();
        assert_eq!(
            v6_mapped_bind_addr(v4),
            "[::ffff:192.0.2.1]:853".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn v6_mapped_bind_addr_keeps_ipv6_binds() {
        let wildcard: SocketAddr = "[::]:853".parse().unwrap();
        assert_eq!(v6_mapped_bind_addr(wildcard), wildcard);
    }
}
