use crate::header::*;

/// Wrapper type for signals in linux.
#[repr(i32)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum Signal {
    SIGKILL = libc::SIGKILL,
    SIGTERM = libc::SIGTERM,
    SIGSTOP = libc::SIGSTOP,
    SIGCONT = libc::SIGCONT,
}

impl From<Signal> for c_int {
    fn from(sig: Signal) -> Self {
        match sig {
            Signal::SIGKILL => libc::SIGKILL,
            Signal::SIGTERM => libc::SIGTERM,
            Signal::SIGSTOP => libc::SIGSTOP,
            Signal::SIGCONT => libc::SIGCONT,

            // exhaustiveness ignored in the crate that defines the enum
            // _ => unimplemented!(),
        }
    }
}

/// Possible state and associated info for any process.
#[derive(PartialEq, Clone, Copy, Debug)]
enum ProcessState {
    Running,
    Stopped(c_int),         // what signal stopped the process
    Terminated(c_int),      // what is the return value of the terminated process
    Signaled(c_int),        // what signal terminated the process
}

pub struct Process {
    pid: pid_t,

    // Terminate if launched, ignore if attached
    terminate_on_end: bool,

    // Process state
    state: ProcessState,
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid == 0 { // invalid pid...should have never happened
            panic!("tried to drop Process struct with pid 0");
        }

        // Detach from the process if its either running or currently stopped via signal.
        // After detaching, terminate the process if it was launched during debug session.
        if self.state == ProcessState::Running || 
            matches!(self.state, ProcessState::Stopped(_)) {

            // If process is running then sig-stop it.
            if self.state == ProcessState::Running {
                match self.send_sig(Signal::SIGSTOP) {
                    None => {
                        // We just did it, so it must succeed.
                        assert_eq!(
                            self.wait_on_signal(),
                            ProcessState::Stopped(Signal::SIGSTOP.into()),
                        );
                    },
                    Some(e) => {
                        // ESRCH => no such process, i.e. process terminated after we 
                        // last checked.
                        if e.0 == libc::ESRCH {
                            return; // nothing else to do in drop
                        } else {
                            // sig_send failed because something worse happened.
                            eprintln!("process signalling error: {e}");
                            std::process::exit(-1);
                        }
                    }
                }
            }

            // Try to detach from the stopped process. It should succeed, otherwise panic.
            if unsafe { libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0) } == -1 {
                let os_error = errno::errno();
                eprintln!("{}:{}: ptrace detach failed: {os_error:?}", file!(), line!());
                std::process::exit(-1);
            }

            // Continue the process after successfully detaching from it.
            assert!(self.send_sig(Signal::SIGCONT).is_none());

            // Terminate the process if it was spawned during debug session.
            if self.terminate_on_end {
                match self.send_sig(Signal::SIGKILL) {
                    Some(e) if e.0 != libc::ESRCH => {
                        // Process did not self terminate and we failed to sig-kill it.
                        eprintln!("could not kill launched process: {e}");
                        std::process::exit(-1);
                    }
                    _ => {}
                }

                println!("INFO: terminated child process for debug session");
            }
        } 
    }
}

impl Process {
    /// Send a signal to process. 
    ///
    /// Return Value: 
    /// `None` if successfully send the signal
    /// `Some(errno)` if failed.
    fn send_sig(&self, sig: Signal) -> Option<errno::Errno> {
        let sig = sig as c_int;
        let result = unsafe {
            libc::kill(self.pid, sig)
        };

        if result < 0 {
            return Some(errno::errno());
        } else {
            return None;
        }
    }

    /// Launch a process with the given pathname.
    ///
    /// Return Value: 
    /// Process struct upon successfully launching.
    /// Exits the program on failure.
    pub fn launch(pathname: &str) -> Self {
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            eprintln!("fork failed");
            std::process::exit(-1);
        }

        // Inside child process
        if pid == 0 {
            // Allow tracing by parent.
            let traceme_status = unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, libc::AT_NULL, libc::AT_NULL)
            };
            if traceme_status < 0 {
                let os_error = errno::errno();
                eprintln!(
                    "{}:{}: PTRACE_TRACEME request failed: {os_error:?}",
                    file!(),
                    line!()
                );
                std::process::exit(-1);
            }

            // Replace the child with correct process
            let pathname = std::ffi::CString::new(pathname)
                .expect("CString new failed");

            // should not return
            let _ = unsafe {
                libc::execlp(pathname.as_ptr(), pathname.as_ptr(), libc::AT_NULL)
            };

            // This code should not run, but if execlp fails then it will, so we exit.
            let os_error = std::io::Error::last_os_error();
            eprintln!("{}:{}: execlp failed: {os_error:?}", file!(), line!());
            std::process::exit(-1);
        }

        // Back to parent
        let mut proc =  Process {
            pid,
            terminate_on_end: true,
            state: ProcessState::Running, // not sure but there is a wait_on_signal() next
        };
        proc.wait_on_signal();

        return proc;
    }

    /// Attach to a running process whose PID is known. 
    ///
    /// Return Value:
    /// Process struct upon success otherwise exits on failure.
    ///
    /// NOTE: use `sudo setcap CAP_SYS_PTRACE=+eip <executable>` to allow
    /// <executable> to attach to any process for tracing.
    pub fn attach(pid: pid_t) -> Self {
        assert!(pid != 0);

        let attach_status = unsafe {
            libc::ptrace(libc::PTRACE_ATTACH, pid, libc::AT_NULL, libc::AT_NULL)
        };
        if attach_status < 0 {
            let os_error = errno::errno();
            eprintln!("{}:{}: process attach failed: {os_error:?}", file!(), line!());
            std::process::exit(-1);
        }

        let mut proc =  Process {
            pid,
            terminate_on_end: false,
            state: ProcessState::Running, // not sure but there is a wait_on_signal() next
        };
        proc.wait_on_signal();

        return proc;
    }

    /// Resumes a stopped process and returns true if the process was resumed.
    pub fn resume(&mut self) -> bool {
        // Return false if process is currently not stopped.
        if !matches!(self.state, ProcessState::Stopped(_)) {
            return false;
        }
        let result = unsafe {
            libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0)
        };

        if result < 0 {
            eprintln!(
                "{}:{}: process resume failed: {}",
                file!(),
                line!(),
                errno::errno()
            );
            std::process::exit(-1);
        }

        // Update state
        self.state = ProcessState::Running;

        return true;
    }

    /// Wait for a running process to stop, exit normally or terminate by signal.
    ///
    /// Return Value:
    /// Current state of the process which also contains the information about
    /// what transition happened.
    fn wait_on_signal(&mut self) -> ProcessState {
        let mut wstatus: c_int = 0;

        if unsafe { libc::waitpid(self.pid, &mut wstatus, 0) } == -1 {
            eprintln!("{}:{}: waiting failed: {}", file!(), line!(), errno::errno());
            std::process::exit(-1);
        }

        // normal temination check.
        if libc::WIFEXITED(wstatus) {
            let exit_status = libc::WEXITSTATUS(wstatus);
            self.state = ProcessState::Terminated(exit_status);
            return self.state;
        }

        // signaled termination check.
        if libc::WIFSIGNALED(wstatus) {
            let term_sig = libc::WTERMSIG(wstatus);
            self.state = ProcessState::Signaled(term_sig);
            return self.state;
        }

        // signaled stop check
        if libc::WIFSTOPPED(wstatus) {
            let stop_signal = libc::WSTOPSIG(wstatus);
            self.state = ProcessState::Stopped(stop_signal);
            return self.state;
        }

        todo!("exit, signaled termination and signaled stopping are not exhaustive \
        ways for a child process to change state");
    }
}

/// Handelling different commands given to the sdb interpreter.
pub mod command {
    use super::*;

    /// Return `true` if `command` is a prefix of `src`
    fn is_prefix(command: &str, src: &str) -> bool {
        // sanity check.
        if command.len() > src.len() || command.len() == 0 {
            return false;
        }

        for (x, y) in command.chars().zip(src.chars()) {
            if x != y {
                return false;
            }
        }

        true
    }

    pub fn handle_command(proc: &mut Process, command: &str) {
        // 'continue' family of commands
        if is_prefix(command, "continue") {
            // resume the process or return if cannot be resumed.
            if !proc.resume() {
                println!("INFO: process is not in a stopped state and cannot be resumed");
                return;
            }

            // wait for process to change state
            let state = proc.wait_on_signal();
            match state {
                ProcessState::Terminated(e) => {
                    println!("INFO: process terminated with exit code: {}", e);
                }
                ProcessState::Signaled(e) => {
                    println!(
                        "INFO: process terminated with signal: {:?}",
                        unsafe {
                            std::ffi::CStr::from_ptr(glibc::sigabbrev_np(e))
                        }
                    );
                }
                ProcessState::Stopped(e) => {
                    println!(
                        "INFO: process stopped with signal: {:?}",
                        unsafe {
                            std::ffi::CStr::from_ptr(glibc::sigabbrev_np(e))
                        }
                    );
                }
                _ => unreachable!(),
            }
        } else {
            eprintln!("unknown command");
        }
    }
}
