#![cfg(target_os = "windows")]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::mem;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, ReadProcessMemory,
    WaitForDebugEvent, WriteProcessMemory, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

const DBG_CONTINUE: NTSTATUS = NTSTATUS(0x00010002u32 as i32);
const DBG_EXCEPTION_NOT_HANDLED: NTSTATUS = NTSTATUS(0x80010001u32 as i32);

const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_FULL: u32 =
    CONTEXT_AMD64 | 0x1 | 0x2 | 0x8;
const CTX_SIZE: usize = 1232;
const OFF_FLAGS: usize = 0x30;
const OFF_EFLAGS: usize = 0x44;
const OFF_RCX: usize = 0x80;
const OFF_RDX: usize = 0x88;
const OFF_RSP: usize = 0x98;
const OFF_R8: usize = 0xB8;
const OFF_R9: usize = 0xC0;
const OFF_RIP: usize = 0xF8;

#[repr(C, align(16))]
struct Ctx([u8; CTX_SIZE]);

impl Ctx {
    fn new(flags: u32) -> Self {
        let mut c = Self([0u8; CTX_SIZE]);
        c.write_u32(OFF_FLAGS, flags);
        c
    }
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().unwrap())
    }
    fn read_u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.0[off..off + 8].try_into().unwrap())
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write_u64(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn rip(&self) -> u64 { self.read_u64(OFF_RIP) }
    fn set_rip(&mut self, v: u64) { self.write_u64(OFF_RIP, v) }
    fn rsp(&self) -> u64 { self.read_u64(OFF_RSP) }
    fn rcx(&self) -> u64 { self.read_u64(OFF_RCX) }
    fn rdx(&self) -> u64 { self.read_u64(OFF_RDX) }
    fn r8(&self) -> u64 { self.read_u64(OFF_R8) }
    fn r9(&self) -> u64 { self.read_u64(OFF_R9) }
    fn eflags(&self) -> u32 { self.read_u32(OFF_EFLAGS) }
    fn set_eflags(&mut self, v: u32) { self.write_u32(OFF_EFLAGS, v) }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetThreadContext(hthread: HANDLE, lpcontext: *mut u8) -> BOOL;
    fn SetThreadContext(hthread: HANDLE, lpcontext: *const u8) -> BOOL;
}

#[derive(Parser)]
#[command(
    name = "vtable-trace",
    version,
    about = "Dump a C++ object's vtable and trace calls to its entries"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Dump {
        #[arg(long)]
        pid: u32,
        #[arg(long, value_parser = parse_hex_usize)]
        obj: usize,
        #[arg(long, default_value_t = 16)]
        entries: usize,
    },
    Trace {
        #[arg(long)]
        pid: u32,
        #[arg(long, value_parser = parse_hex_usize, conflicts_with = "addr", requires = "slot")]
        obj: Option<usize>,
        #[arg(long, requires = "obj")]
        slot: Option<usize>,
        #[arg(long, value_parser = parse_hex_usize, conflicts_with_all = ["obj", "slot"])]
        addr: Option<usize>,
        #[arg(long, default_value_t = 8)]
        stack_words: usize,
        #[arg(long)]
        max_hits: Option<u64>,
    },
}

fn parse_hex_usize(s: &str) -> Result<usize, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X").replace('_', "");
    usize::from_str_radix(&s, 16).map_err(|e| format!("not a hex address: {e}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Dump { pid, obj, entries } => cmd_dump(pid, obj, entries),
        Command::Trace { pid, obj, slot, addr, stack_words, max_hits } => {
            cmd_trace(pid, obj, slot, addr, stack_words, max_hits)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct ModuleSpan {
    name: String,
    base: usize,
    size: usize,
}

fn enumerate_modules(pid: u32) -> Result<Vec<ModuleSpan>, String> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) }
        .map_err(|e| format!("snapshot pid {pid}: {e}"))?;
    let _g = HandleGuard(snap);

    let mut me: MODULEENTRY32W = unsafe { mem::zeroed() };
    me.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
    let mut out = Vec::new();
    let mut ok = unsafe { Module32FirstW(snap, &mut me) }.is_ok();
    while ok {
        let n = me
            .szModule
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(me.szModule.len());
        let name = String::from_utf16_lossy(&me.szModule[..n]);
        out.push(ModuleSpan {
            name,
            base: me.modBaseAddr as usize,
            size: me.modBaseSize as usize,
        });
        ok = unsafe { Module32NextW(snap, &mut me) }.is_ok();
    }
    out.sort_by_key(|m| m.base);
    Ok(out)
}

fn locate(modules: &[ModuleSpan], addr: usize) -> Option<(&str, usize)> {
    for m in modules {
        if addr >= m.base && addr < m.base + m.size {
            return Some((&m.name, addr - m.base));
        }
    }
    None
}

fn cmd_dump(pid: u32, obj: usize, entries: usize) -> Result<(), String> {
    let proc = unsafe { OpenProcess(PROCESS_VM_READ, false, pid) }
        .map_err(|e| format!("OpenProcess({pid}): {e}"))?;
    let _g = HandleGuard(proc);

    let modules = enumerate_modules(pid)?;

    let vtable = read_qword(proc, obj)?;
    println!("object  : 0x{obj:016x}");
    println!("vtable  : 0x{vtable:016x}");
    if let Some((name, off)) = locate(&modules, vtable as usize) {
        println!("vtable in: {name} +0x{off:x}");
    }
    println!("entries : {entries}");
    println!();
    println!("{:<4} {:<18} {:<12} OFFSET", "SLOT", "ABSOLUTE", "MODULE");

    for i in 0..entries {
        let entry_addr = vtable as usize + i * 8;
        let func = match read_qword(proc, entry_addr) {
            Ok(v) => v,
            Err(_) => {
                println!("{i:<4} (read failed at 0x{entry_addr:x})");
                break;
            }
        };
        if func == 0 {
            println!("{i:<4} 0x{func:016x}  (null)", );
            continue;
        }
        match locate(&modules, func as usize) {
            Some((name, off)) => {
                println!("{i:<4} 0x{func:016x}  {name:<12} +0x{off:x}");
            }
            None => {
                println!("{i:<4} 0x{func:016x}  (unmapped)");
            }
        }
    }

    Ok(())
}

fn cmd_trace(
    pid: u32,
    obj: Option<usize>,
    slot: Option<usize>,
    addr: Option<usize>,
    stack_words: usize,
    max_hits: Option<u64>,
) -> Result<(), String> {
    let target_addr = match (addr, obj, slot) {
        (Some(a), _, _) => a,
        (None, Some(o), Some(s)) => {
            let proc = unsafe { OpenProcess(PROCESS_VM_READ, false, pid) }
                .map_err(|e| format!("OpenProcess for resolve({pid}): {e}"))?;
            let _g = HandleGuard(proc);
            let vtable = read_qword(proc, o)? as usize;
            let entry = read_qword(proc, vtable + s * 8)? as usize;
            eprintln!("resolved obj 0x{o:x} slot {s} -> 0x{entry:x}");
            entry
        }
        _ => return Err("trace requires --addr or (--obj + --slot)".into()),
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_signal = stop.clone();
    ctrlc_set(move || stop_signal.store(true, Ordering::SeqCst))?;

    let proc = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            pid,
        )
    }
    .map_err(|e| format!("OpenProcess({pid}): {e}"))?;
    let _g_proc = HandleGuard(proc);

    let original_byte = read_byte(proc, target_addr)?;
    write_byte(proc, target_addr, 0xCC)?;

    unsafe { DebugActiveProcess(pid) }
        .map_err(|e| format!("DebugActiveProcess({pid}): {e}"))?;
    let detach = Detacher {
        proc,
        addr: target_addr,
        byte: original_byte,
        pid,
    };

    eprintln!(
        "attached to pid {pid} — INT3 at 0x{target_addr:x}; Ctrl+C to detach"
    );

    let mut hits: u64 = 0;
    let mut last_thread: Option<(u32, HANDLE)> = None;

    while !stop.load(Ordering::SeqCst) {
        let mut event: DEBUG_EVENT = unsafe { mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut event, 250) }.is_err() {
            continue;
        }

        let mut status = DBG_CONTINUE;
        match event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let exc = unsafe { event.u.Exception };
                let code = exc.ExceptionRecord.ExceptionCode;
                let exc_addr = exc.ExceptionRecord.ExceptionAddress as usize;

                if code == EXCEPTION_BREAKPOINT && exc_addr == target_addr {
                    hits += 1;
                    let thread = unsafe {
                        OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                            false,
                            event.dwThreadId,
                        )
                    }
                    .map_err(|e| format!("OpenThread({}): {e}", event.dwThreadId))?;

                    let mut ctx = Ctx::new(CONTEXT_FULL);
                    if unsafe { GetThreadContext(thread, ctx.0.as_mut_ptr()) }.0 == 0 {
                        return Err("GetThreadContext failed".into());
                    }
                    ctx.set_rip(ctx.rip().saturating_sub(1));

                    let ret = read_qword(proc, ctx.rsp() as usize).unwrap_or(0);
                    print_hit(hits, event.dwThreadId, ctx.rip(), ret, &ctx);
                    if stack_words > 0 {
                        print_stack(proc, ctx.rsp() as usize, stack_words);
                    }

                    write_byte(proc, target_addr, original_byte)?;
                    let ef = ctx.eflags();
                    ctx.set_eflags(ef | 0x100);
                    if unsafe { SetThreadContext(thread, ctx.0.as_ptr()) }.0 == 0 {
                        return Err("SetThreadContext failed".into());
                    }

                    if let Some((_, old)) = last_thread.replace((event.dwThreadId, thread)) {
                        unsafe {
                            let _ = CloseHandle(old);
                        }
                    }

                    if let Some(max) = max_hits {
                        if hits >= max {
                            eprintln!("max-hits reached, detaching");
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                } else if code == EXCEPTION_SINGLE_STEP {
                    write_byte(proc, target_addr, 0xCC)?;
                    if let Some((_, h)) = last_thread.take() {
                        unsafe {
                            let _ = CloseHandle(h);
                        }
                    }
                } else if code == EXCEPTION_BREAKPOINT {
                    // unrelated INT3 (loader breakpoint, etc.) — let it through
                } else {
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                eprintln!("target exited");
                break;
            }
            _ => {}
        }

        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
            .map_err(|e| format!("ContinueDebugEvent: {e}"))?;
    }

    drop(detach);
    eprintln!("done — {hits} hit(s)");
    Ok(())
}

struct Detacher {
    proc: HANDLE,
    addr: usize,
    byte: u8,
    pid: u32,
}

impl Drop for Detacher {
    fn drop(&mut self) {
        let _ = write_byte(self.proc, self.addr, self.byte);
        unsafe {
            let _ = DebugActiveProcessStop(self.pid);
        }
    }
}

fn ctrlc_set<F: Fn() + Send + Sync + 'static>(f: F) -> Result<(), String> {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    static mut HANDLER: Option<Box<dyn Fn() + Send + Sync>> = None;
    unsafe extern "system" fn dispatch(_ctrl_type: u32) -> BOOL {
        if let Some(h) = HANDLER.as_ref() {
            h();
        }
        BOOL(1)
    }
    unsafe {
        HANDLER = Some(Box::new(f));
        SetConsoleCtrlHandler(Some(dispatch), true)
            .map_err(|e| format!("SetConsoleCtrlHandler: {e}"))?;
    }
    Ok(())
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn read_byte(proc: HANDLE, addr: usize) -> Result<u8, String> {
    let mut b = 0u8;
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            proc,
            addr as *const c_void,
            &mut b as *mut _ as *mut c_void,
            1,
            Some(&mut n),
        )
    }
    .map_err(|e| format!("ReadProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 1 {
        return Err(format!("short read at 0x{addr:x}"));
    }
    Ok(b)
}

fn write_byte(proc: HANDLE, addr: usize, b: u8) -> Result<(), String> {
    let mut n = 0usize;
    unsafe {
        WriteProcessMemory(
            proc,
            addr as *mut c_void,
            &b as *const _ as *const c_void,
            1,
            Some(&mut n),
        )
    }
    .map_err(|e| format!("WriteProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 1 {
        return Err(format!("short write at 0x{addr:x}"));
    }
    Ok(())
}

fn read_qword(proc: HANDLE, addr: usize) -> Result<u64, String> {
    let mut buf = [0u8; 8];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            8,
            Some(&mut n),
        )
    }
    .map_err(|e| format!("ReadProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 8 {
        return Err(format!("short read at 0x{addr:x}"));
    }
    Ok(u64::from_le_bytes(buf))
}

fn print_hit(n: u64, tid: u32, rip: u64, ret: u64, ctx: &Ctx) {
    println!(
        "[hit {n:>3}] tid={tid}  rip=0x{rip:016x}  ret=0x{ret:016x}\n         rcx=0x{:016x}  rdx=0x{:016x}\n         r8 =0x{:016x}  r9 =0x{:016x}",
        ctx.rcx(),
        ctx.rdx(),
        ctx.r8(),
        ctx.r9()
    );
}

fn print_stack(proc: HANDLE, rsp: usize, words: usize) {
    let mut bytes = vec![0u8; words * 8];
    let mut n = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            proc,
            rsp as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            Some(&mut n),
        )
    };
    if ok.is_err() {
        return;
    }
    let read = n / 8;
    let mut line = String::from("         stack: ");
    for i in 0..read {
        let w = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        line.push_str(&format!("{w:016x} "));
    }
    println!("{}", line.trim_end());
}
