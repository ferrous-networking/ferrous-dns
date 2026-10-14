//! Reads of the machine Ferrous runs on, for the `/info/*` routes. They read
//! the same `/proc` and `/sys` files FTL does; where a file is missing (or off
//! Linux) a value is 0 or null. All of them block, so call them from
//! `spawn_blocking`.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::dto::info::{
    DatabaseOwner, DatabaseOwnerGroup, DatabaseOwnerUser, DmiBoard, DmiProduct, DmiVendor, HostDmi,
    HostInfo, HostUname, ProcessUsage, RamInfo, SwapInfo, SystemCpu, SystemInfo, SystemLoad,
    SystemMemory,
};

/// FTL caps the process memory share just below 100%.
const MAX_PROCESS_MEM_PERCENT: f64 = 99.9;

/// `/proc/meminfo` values, in kB.
#[derive(Default)]
struct MemInfo {
    total: u64,
    free: u64,
    available: u64,
    page_cached: u64,
    buffers: u64,
    slab_reclaimable: u64,
    swap_total: u64,
    swap_free: u64,
}

impl MemInfo {
    fn read() -> Self {
        let Ok(content) = std::fs::read_to_string("/proc/meminfo") else {
            return Self::default();
        };
        let mut mem = Self::default();
        for line in content.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let field = match key {
                "MemTotal" => &mut mem.total,
                "MemFree" => &mut mem.free,
                "MemAvailable" => &mut mem.available,
                "Cached" => &mut mem.page_cached,
                "Buffers" => &mut mem.buffers,
                "SReclaimable" => &mut mem.slab_reclaimable,
                "SwapTotal" => &mut mem.swap_total,
                "SwapFree" => &mut mem.swap_free,
                _ => continue,
            };
            *field = parse_kb_value(value);
        }
        mem
    }

    /// As `free` (procps) computes them; inside an LXC container the host's
    /// numbers can exceed the container's total, so fall back to plain free.
    fn ram(&self) -> RamInfo {
        let reclaimable = self.page_cached + self.slab_reclaimable + self.buffers;
        let used = if self.total >= self.free + reclaimable {
            self.total - self.free - reclaimable
        } else {
            self.total.saturating_sub(self.free)
        };
        let available = if self.available > self.total {
            self.free
        } else {
            self.available
        };
        RamInfo {
            total: self.total,
            free: self.free,
            used,
            available,
            used_percent: percent(used as f64, self.total as f64),
        }
    }

    fn swap(&self) -> SwapInfo {
        let used = self.swap_total.saturating_sub(self.swap_free);
        SwapInfo {
            total: self.swap_total,
            free: self.swap_free,
            used,
            used_percent: percent(used as f64, self.swap_total as f64),
        }
    }
}

pub(crate) fn read_system() -> SystemInfo {
    let mem = MemInfo::read();
    let (raw, procs) = read_loadavg();
    let nprocs = configured_processors();
    let load_percent = raw.map(|load| percent(load, nprocs as f64));
    SystemInfo {
        uptime: read_host_uptime(),
        memory: SystemMemory {
            ram: mem.ram(),
            swap: mem.swap(),
        },
        procs,
        cpu: SystemCpu {
            nprocs,
            cpu_percent: 0.0,
            load: SystemLoad {
                raw,
                percent: load_percent,
            },
        },
        ftl: ProcessUsage {
            mem_percent: process_mem_percent(mem.total),
            cpu_percent: 0.0,
        },
    }
}

/// This process's resident memory as a share of the host's.
pub(crate) fn read_process_mem_percent() -> f64 {
    process_mem_percent(MemInfo::read().total)
}

fn process_mem_percent(total_kb: u64) -> f64 {
    let rss_kb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .map(parse_kb_value)
        })
        .unwrap_or(0);
    percent(rss_kb as f64, total_kb as f64).min(MAX_PROCESS_MEM_PERCENT)
}

pub(crate) fn read_host() -> HostInfo {
    let dmi = |name: &str| read_sys_property(&format!("/sys/devices/virtual/dmi/id/{name}"));
    HostInfo {
        uname: read_uname(),
        model: read_sys_property("/sys/firmware/devicetree/base/model"),
        dmi: HostDmi {
            bios: DmiVendor {
                vendor: dmi("bios_vendor"),
            },
            board: DmiBoard {
                name: dmi("board_name"),
                vendor: dmi("board_vendor"),
                version: dmi("board_version"),
            },
            product: DmiProduct {
                name: dmi("product_name"),
                family: dmi("product_family"),
                version: dmi("product_version"),
            },
            sys: DmiVendor {
                vendor: dmi("sys_vendor"),
            },
        },
    }
}

/// The database file's `stat`, as FTL reports it for its own database.
pub(crate) struct DatabaseFile {
    pub size: u64,
    pub file_type: &'static str,
    pub mode: String,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub owner: DatabaseOwner,
}

/// A file that cannot be read reports as FTL's zeroed `stat` does: an
/// `Unknown` type with no permissions, owned by nobody known.
pub(crate) fn read_database_file(path: &Path) -> DatabaseFile {
    let Ok(meta) = std::fs::metadata(path) else {
        return DatabaseFile {
            size: 0,
            file_type: "Unknown",
            mode: permission_string(0),
            atime: 0,
            mtime: 0,
            ctime: 0,
            owner: DatabaseOwner {
                user: DatabaseOwnerUser {
                    uid: 0,
                    name: None,
                    info: None,
                },
                group: DatabaseOwnerGroup { gid: 0, name: None },
            },
        };
    };
    // `metadata` follows links, so FTL's third type, `Symbolic link`, never shows.
    let file_type = if meta.is_file() {
        "Regular file"
    } else {
        "Unknown"
    };
    let (user_name, user_info) = match lookup_user(meta.uid()) {
        Some((name, info)) => (Some(name), Some(info)),
        None => (None, None),
    };
    DatabaseFile {
        size: meta.size(),
        file_type,
        mode: permission_string(meta.mode()),
        atime: meta.atime(),
        mtime: meta.mtime(),
        ctime: meta.ctime(),
        owner: DatabaseOwner {
            user: DatabaseOwnerUser {
                uid: meta.uid(),
                name: user_name,
                info: user_info,
            },
            group: DatabaseOwnerGroup {
                gid: meta.gid(),
                name: lookup_group(meta.gid()),
            },
        },
    }
}

/// Permissions as `ls` prints them, without the type: `rw-r--r--`.
fn permission_string(mode: u32) -> String {
    const FLAGS: [(u32, char); 9] = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    FLAGS
        .iter()
        .map(|&(bit, flag)| if mode & bit != 0 { flag } else { '-' })
        .collect()
}

/// `(name, gecos)` of `uid` in `/etc/passwd`.
fn lookup_user(uid: u32) -> Option<(String, String)> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let entry_uid: u32 = fields.nth(1)?.parse().ok()?;
        let gecos = fields.nth(1)?;
        (entry_uid == uid).then(|| (name.to_string(), gecos.to_string()))
    })
}

/// Name of `gid` in `/etc/group`.
fn lookup_group(gid: u32) -> Option<String> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let entry_gid: u32 = fields.nth(1)?.parse().ok()?;
        (entry_gid == gid).then(|| name.to_string())
    })
}

/// First line of a `/sys` attribute, null when the host does not expose it.
/// Device-tree strings end in a NUL, which C reads as the end of the string.
fn read_sys_property(path: &str) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let line = content.split(|&b| b == b'\n' || b == 0).next()?;
    Some(String::from_utf8_lossy(line).into_owned())
}

/// Seconds since the host booted.
fn read_host_uptime() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0, |secs| secs as u64)
}

/// The three load averages and the number of processes (threads included),
/// the fourth field's denominator.
fn read_loadavg() -> ([f64; 3], u64) {
    let Ok(content) = std::fs::read_to_string("/proc/loadavg") else {
        return ([0.0; 3], 0);
    };
    let mut fields = content.split_whitespace();
    let mut load = || fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let raw = [load(), load(), load()];
    let procs = content
        .split_whitespace()
        .nth(3)
        .and_then(|running_total| running_total.split_once('/'))
        .and_then(|(_, total)| total.parse().ok())
        .unwrap_or(0);
    (raw, procs)
}

fn parse_kb_value(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn percent(part: f64, whole: f64) -> f64 {
    if whole > 0.0 {
        100.0 * part / whole
    } else {
        0.0
    }
}

/// Configured rather than online processors, as FTL counts them, so a
/// virtual machine with CPUs offline still reports its full size.
#[cfg(target_os = "linux")]
fn configured_processors() -> u64 {
    // SAFETY: sysconf takes no pointers and only reads a system setting.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    u64::try_from(count).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn configured_processors() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn read_uname() -> HostUname {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uts` is writable storage for exactly one `utsname`, which is
    // all the call writes.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return HostUname::default();
    }
    // SAFETY: uname returned 0, so it initialised every field of `uts`.
    let uts = unsafe { uts.assume_init() };
    HostUname {
        domainname: c_chars_to_string(&uts.domainname),
        machine: c_chars_to_string(&uts.machine),
        nodename: c_chars_to_string(&uts.nodename),
        release: c_chars_to_string(&uts.release),
        sysname: c_chars_to_string(&uts.sysname),
        version: c_chars_to_string(&uts.version),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_uname() -> HostUname {
    HostUname::default()
}

/// A NUL-terminated `utsname` field; the kernel always terminates them.
#[cfg(target_os = "linux")]
fn c_chars_to_string(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_string_prints_mode_bits_as_ls_does() {
        assert_eq!(permission_string(0o100644), "rw-r--r--");
        assert_eq!(permission_string(0o750), "rwxr-x---");
        assert_eq!(permission_string(0), "---------");
    }

    #[test]
    fn ram_used_leaves_out_cache_and_buffers() {
        let mem = MemInfo {
            total: 1000,
            free: 200,
            available: 600,
            page_cached: 250,
            buffers: 50,
            slab_reclaimable: 100,
            ..MemInfo::default()
        };
        let ram = mem.ram();
        assert_eq!(ram.used, 400);
        assert_eq!(ram.used_percent, 40.0);
        assert_eq!(ram.available, 600);
    }

    #[test]
    fn database_file_reports_size_type_and_owner() {
        let path = std::env::temp_dir().join(format!("ferrous-info-db-{}", std::process::id()));
        std::fs::write(&path, b"12345").expect("failed to write the file");
        let meta = std::fs::metadata(&path).expect("failed to stat the file");

        let file = read_database_file(&path);
        std::fs::remove_file(&path).expect("failed to remove the file");

        assert_eq!(file.size, 5);
        assert_eq!(file.file_type, "Regular file");
        assert_eq!(file.mode, permission_string(meta.mode()));
        assert_eq!(file.mtime, meta.mtime());
        assert_eq!(file.owner.user.uid, meta.uid());
        assert_eq!(file.owner.group.gid, meta.gid());
    }
}
