use std::{error::Error, os::fd::AsFd, ptr::null_mut};

use fanotify::high_level::*;
use nix::{
    libc::{MAP_POPULATE, MAP_PRIVATE, O_LARGEFILE, O_NOATIME, O_RDONLY, PROT_READ},
    poll::{PollFd, PollFlags, PollTimeout, poll},
};

fn main() -> Result<(), Box<dyn Error>> {
    let app = clap::Command::new("with_poll")
        .arg(clap::Arg::new("path").index(1).required(true))
        .get_matches();

    let app_path = app
        .get_one::<String>("path")
        .expect("We can unwrap here as clap enforces the existence of `path`");

    let fd = fanotify::high_level::FanotifyBuilder::new()
        .with_class(FanotifyMode::CONTENT)
        .with_event_flags((O_LARGEFILE | O_NOATIME | O_RDONLY) as u32)
        .register();

    match fd {
        Ok(fdb) => {
            fdb.add_mountpoint(FAN_OPEN, app_path).unwrap();

            let fd_handle = fdb.as_fd();
            let mut fds = [PollFd::new(fd_handle, PollFlags::POLLIN)];
            loop {
                let poll_num = poll(&mut fds, PollTimeout::MAX)?;
                if poll_num > 0 {
                    for event in fdb.read_event() {
                        let mut stat = unsafe {core::mem::zeroed()};
                        let stat_rc = unsafe {nix::libc::fstat(event.fd, &mut stat)};
                        if stat_rc < 0 {
                            eprintln!("failed to read file descriptor for file size (err: {}). Continuing...", std::io::Error::last_os_error());
                            continue;
                        }

                        println!("event: {:#?}", &event);
                        println!("lib stat: {:#?}", &stat);
                        match unsafe {nix::libc::mmap(null_mut(), stat.st_size as _, PROT_READ, MAP_POPULATE | MAP_PRIVATE, event.fd, 0)} {
                            ptr if ptr == null_mut() => {
                                eprintln!("Failed to map requested file (err: {}). Continuing...", std::io::Error::last_os_error());
                            }
                            ptr => {
                                println!("reading {} for eicar string", &event.path);
                                let buf = unsafe {std::slice::from_raw_parts(ptr as *const u8, stat.st_size as _)};
                                if memchr::memmem::find(buf, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").is_some() {
                                    println!("Found eicar string in file \"{}\"", &event.path);
                                }

                                unsafe {nix::libc::munmap(ptr, stat.st_size as _)};
                            }
                        }
                        fdb.send_response(event.fd, FanotifyResponse::Allow);
                    }
                } else {
                    eprintln!("poll_num <= 0!");
                    break;
                }
            }
        }
        Err(e) => {
            println!("encountered an error while creating fanotify context: {e}")
        }
    }

    Ok(())
}
