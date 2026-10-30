use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

use crate::error::NetworkError;
use crate::names::IFNAMSIZ_MAX_LEN;

const TUN_DEVICE: &str = "/dev/net/tun";

pub(crate) fn create_persistent_tap(name: &str, uid: u32, gid: u32) -> Result<(), NetworkError>
{
    if name.is_empty() || name.len() > IFNAMSIZ_MAX_LEN
    {
        return Err(NetworkError::io(
            format!("tap name {name:?} does not fit IFNAMSIZ"),
            std::io::Error::from(std::io::ErrorKind::InvalidInput),
        ));
    }
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE)
        .map_err(|e| NetworkError::io(format!("opening {TUN_DEVICE}"), e))?;
    let fd = device.as_raw_fd();

    // SAFETY: ifreq is plain old data; an all-zero value is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes())
    {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags =
        (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;

    let check = |result: libc::c_int, action: &str| {
        if result < 0
        {
            Err(NetworkError::io(
                format!("{action} for tap {name}"),
                std::io::Error::last_os_error(),
            ))
        }
        else
        {
            Ok(())
        }
    };
    // SAFETY: fd is an open /dev/net/tun descriptor and request outlives the call.
    check(
        unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut request) },
        "TUNSETIFF",
    )?;
    // SAFETY: TUNSET{OWNER,GROUP,PERSIST} take their argument by value.
    check(
        unsafe { libc::ioctl(fd, libc::TUNSETOWNER, libc::c_ulong::from(uid)) },
        "TUNSETOWNER",
    )?;
    check(
        unsafe { libc::ioctl(fd, libc::TUNSETGROUP, libc::c_ulong::from(gid)) },
        "TUNSETGROUP",
    )?;
    check(
        unsafe { libc::ioctl(fd, libc::TUNSETPERSIST, 1 as libc::c_ulong) },
        "TUNSETPERSIST",
    )
}
