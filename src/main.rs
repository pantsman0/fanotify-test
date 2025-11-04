use std::{
    collections::{HashMap, HashSet},
    os::fd::AsFd,
    ptr::null_mut,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use concurrent_queue::{ConcurrentQueue, PopError};
use fanotify::high_level::*;
use nix::{
    libc::{MAP_POPULATE, MAP_PRIVATE, O_LARGEFILE, O_NOATIME, O_RDONLY, PROT_READ},
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use threadpool::ThreadPool;

static STOP: AtomicBool = AtomicBool::new(false);
fn main() -> anyhow::Result<()> {
    let app = clap::Command::new("fanotify-test")
        .arg(clap::Arg::new("path").index(1).required(true))
        .get_matches();

    let app_path = app
        .get_one::<String>("path")
        .expect("We can unwrap here as clap enforces the existence of `path`");

    let notify_handle = fanotify::high_level::FanotifyBuilder::new()
        .with_class(FanotifyMode::CONTENT)
        .with_event_flags((O_LARGEFILE | O_NOATIME | O_RDONLY) as u32)
        .register()?;

    let thread_count = num_cpus::get_physical() * 2;
    let pool = ThreadPool::new(thread_count);
    let event_queue: Arc<ConcurrentQueue<Event>> = Arc::new(ConcurrentQueue::bounded(thread_count));
    //let child_pids = Arc::new(RwLock::new(HashSet::new()));
    for worker_thread_id in 1..=thread_count {
        let event_queue = event_queue.clone();
        let notify_handle = notify_handle.clone();
        //let child_pids = child_pids.clone();
        pool.execute(move || {
            println!("Started worker thread {}.", worker_thread_id);
            while !STOP.load(Ordering::Relaxed) {
                match event_queue.pop() {
                    Ok(event) => {
                        if //{ !child_pids.read().unwrap().contains(&event.pid) } &&
                             let Ok(environ) =
                                std::fs::read_to_string(format!("/proc/{}/environ", event.pid))
                        {
                            notify_handle.send_response(event.fd, FanotifyResponse::Allow);
                            //println!("environ: {:?}", &environ);
                            let environ: HashMap<String, String> = environ
                                .split('\0')
                                .filter(|line| line.contains('='))
                                .map(|entry| entry.split_once('=').unwrap())
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect();
                            match unsafe { nix::libc::fork() } {
                                0 => unsafe {
                                    let _ = nix::env::clearenv();

                                    environ.iter().for_each(|(k, v)| {
                                        std::env::set_var(k, v);
                                    });

                                    let mut stat = core::mem::zeroed();
                                    let stat_rc = nix::libc::fstat(event.fd, &mut stat);
                                    if stat_rc >= 0
                                        && let data_map = nix::libc::mmap(
                                            null_mut(),
                                            stat.st_size as _,
                                            PROT_READ,
                                            MAP_POPULATE | MAP_PRIVATE,
                                            event.fd,
                                            0,
                                        )
                                        && data_map != null_mut()
                                    {
                                        //println!("reading {} for eicar string", &event.path);
                                        let buf = std::slice::from_raw_parts(data_map as *const u8, stat.st_size as _) ;
                                        if memchr::memmem::find(buf, include_bytes!("../eicar.txt")).is_some() {
                                                    println!("Found eicar string in file \"{}\"", &event.path);
                                        }

                                        nix::libc::munmap(data_map, stat.st_size as _) ;
                                        std::process::exit(0);
                                    } else {
                                        eprintln!(
                                            "unable to map file (err: {}). Continuing...",
                                            std::io::Error::last_os_error()
                                        );
                                    }

                                    
                                },
                                child_pid => {
                                    //child_pids.write().unwrap().insert(child_pid);
                                }
                            }
                        } else {
                            notify_handle.send_response(event.fd, FanotifyResponse::Allow);
                            eprintln!("couldn't read/parse environment for pid {}", event.pid);
                        }
                    }
                    Err(PopError::Empty) => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(PopError::Closed) => {
                        eprintln!(
                            "Event queue closed. shutting down worker thread {}.",
                            worker_thread_id
                        );
                        return;
                    }
                }
            }
        })
    }

    notify_handle.add_mountpoint(FAN_OPEN_PERM, app_path)?;

    let fd_handle = notify_handle.as_fd();
    let mut fds = [PollFd::new(fd_handle, PollFlags::POLLIN)];
    while !STOP.load(std::sync::atomic::Ordering::Relaxed) {
        let poll_num = poll(&mut fds, PollTimeout::MAX)?;
        if poll_num > 0 {
            for event in notify_handle.read_event() {
                if let Err(e) = event_queue.push(event) {
                    eprintln!("Failed to push event to service threads (err: {})", e);
                }
            }
        } else {
            eprintln!("poll_num <= 0!");
            break;
        }
    }

    Ok(())
}
