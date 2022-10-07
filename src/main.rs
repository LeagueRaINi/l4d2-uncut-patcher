use std::env;
use std::ops::Add;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use external::prelude::{EnumModules, IntPtr, IntPtr64, ModuleEntry};
use external::process::{Process, ProcessId, ProcessRights};
use external::thread::{EnumThreads, Thread, ThreadRights};
use external::window::{find, Window};
use regex::bytes::Regex;

type Ptr<T = u8> = IntPtr<T>;

#[derive(Parser, Debug)]
#[clap(about, author, version)]
struct Opt {
    /// If true the patcher will stay open and will keep looking for new instances of Left 4 Dead 2
    #[arg(long, default_value_t = false)]
    keep_open: bool,
}

#[inline(always)]
fn as_ptr<T: ?Sized>(unit_ptr: usize) -> Ptr<T> {
    unsafe { std::mem::transmute(unit_ptr) }
}

fn find_pattern(bytes: &[u8], patt: &'static str) -> Result<Vec<usize>> {
    let regex =
        Regex::new(&["(?s-u)", patt].concat()).context("Failed to create regex from string")?;

    let cap = regex.captures_iter(bytes);
    let cap = cap.filter_map(|capture| (1..capture.len()).find_map(|x| capture.get(x)));

    let offsets = cap.map(|off| off.start()).collect::<Vec<usize>>();
    if !offsets.is_empty() {
        return Ok(offsets);
    }

    bail!("Pattern not found")
}

fn dump_module(proc: &Process, module_entry: &ModuleEntry) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; module_entry.size()];
    proc.vm_read_partial(as_ptr(module_entry.base()), &mut buffer)
        .context("Failed to dump module")?;

    Ok(buffer)
}

fn resume_process(proc_id: ProcessId) -> Result<()> {
    let threads = EnumThreads::create().context("Failed to collect running threads")?;
    let threads = threads.filter(|thread| thread.process_id() == proc_id);

    threads.for_each(|thread_entry| {
        if let Ok(thread) =
            Thread::attach(thread_entry.thread_id(), false, ThreadRights::new().suspend_resume())
        {
            loop {
                if matches!(thread.resume(), Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    });

    Ok(())
}

fn suspend_process(proc_id: ProcessId) -> Result<()> {
    let threads = EnumThreads::create().context("Failed to collect running threads")?;
    let threads = threads.filter(|thread| thread.process_id() == proc_id);

    threads.for_each(|thread_entry| {
        if let Ok(thread) =
            Thread::attach(thread_entry.thread_id(), false, ThreadRights::new().suspend_resume())
        {
            let _ = thread.suspend();
        }
    });

    Ok(())
}

fn wait_for_module(pid: ProcessId, mod_name: &'static str) -> ModuleEntry {
    loop {
        match EnumModules::create(pid)
            .ok()
            .and_then(|mut modules| modules.find(|x| x.name() == mod_name))
        {
            Some(module) => break module,
            _ => sleep(Duration::from_millis(150)),
        }
    }
}

fn wait_for_window(wnd_class: &'static str, wnd_name: &'static str) -> Window {
    loop {
        match find(Some(&wnd_class), Some(&wnd_name)) {
            Ok(wnd) => break wnd,
            _ => sleep(Duration::from_millis(150)),
        }
    }
}

fn main() -> Result<()> {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));

    pretty_env_logger::init();

    let Opt { keep_open } = Opt::parse();

    loop {
        log::info!("Waiting for Left 4 Dead 2...");

        let proc_wnd = wait_for_window("Valve001", "Left 4 Dead 2 - Direct3D 9");
        let proc_id = proc_wnd.thread_process_id().1;
        let proc = Process::attach(proc_id, ProcessRights::ALL_ACCESS)
            .context("Failed to attach to Left 4 Dead 2!")?;

        log::info!("Dumping engine.dll...");

        let engine = wait_for_module(proc_id, "engine.dll");
        let engine_buf = dump_module(&proc, &engine)?;

        {
            let _guard = drop_guard::guard(suspend_process(proc_id), |res| {
                if res.is_ok() && resume_process(proc_id).is_err() {
                    log::error!("Failed to resume process");
                }
            });

            log::info!("Processing patterns...");

            let is_low_violence = || -> Result<bool> {
                let low_violence_var = find_pattern(&engine_buf, "\\xA2(....)\\xEB\\x37")
                    .context("Low violance variable pattern not found")?;
                let low_violence_var = proc
                    .vm_read::<u32>(as_ptr(engine.base().add(low_violence_var[0])))
                    .context("Failed to read low violance variable address")?;
                let low_violence_var = proc
                    .vm_read::<u8>(as_ptr(low_violence_var as _))
                    .context("Failed to read low violance variable")?;

                if !matches!(low_violence_var, 0 | 1) {
                    bail!("Unexpected value, low violence variable pattern may be outdated!");
                }

                Ok(low_violence_var == 1)
            };

            if is_low_violence()? {
                log::error!("Low violance mode has already been initialized, restart the game and try again");
            } else {
                let patch_addr = find_pattern(&engine_buf, "(\\x75\\x10)\\x84\\xC0\\x75\\x0C")
                    .context("Pattern required for patching could not be found")?;

                log::info!("Patching...");

                proc.vm_write_bytes(as_ptr(engine.base().add(patch_addr[0])), &[0x32, 0xC0])
                    .context("Failed to apply patch")?;
            }
        }

        if !keep_open {
            log::info!("Done");
            break;
        }

        log::info!("Waiting for process to exit...");

        while proc.exit_code() == Ok(None) {
            sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}
