use libsdb::sdb;
use libsdb::header::*;

use std::io::Write;

struct History(Vec<String>);

impl History {
    fn last(&self) -> Option<&str> {
        self.0.last().map(|x| x.as_str())
    }
}

fn main() {
    /*
    println!(
        "glibc version: {:?}",
        unsafe { std::ffi::CStr::from_ptr(glibc::gnu_get_libc_version()) },
    );
    */

    let args = std::env::args().collect::<Vec<String>>();
    if args.len() == 1 {
        println!("usage:\n{} <executable>\n{} -p <PID>", &args[0], &args[0]);
        std::process::exit(0);
    }

    let mut proc = if args.len() == 3 && args[1] == "-p" {
        // Attach to existing PID
        let pid = args[2].parse::<pid_t>().expect("pid parse failed");
        sdb::Process::attach(pid)
    } else if args.len() == 2 {
        // launch process from pathname passed to cli
        sdb::Process::launch(&args[1])
    } else {
        unreachable!();
    };

    main_loop(&mut proc);

}

fn main_loop(proc: &mut sdb::Process) {
    let mut input_buf = String::new();

    let mut history = History(Vec::new());

    loop {
        print!("sdb> ");
        std::io::stdout().flush().unwrap();
        if std::io::stdin().read_line(&mut input_buf).unwrap() == 0 {
            break;
        }
        let mut command = input_buf.trim();
        if command.is_empty() {
            if history.last().is_none() {
                println!("// no history");
                input_buf.clear();
                continue;
            } else {
                command = history.0.last().unwrap();
            }
            sdb::command::handle_command(proc, command);
        } else {
            match history.last() {
                Some(last) if last != command => {
                    history.0.push(command.to_string());
                }
                Some(_) => {}
                None => {
                    history.0.push(command.to_string());
                }
            }
            sdb::command::handle_command(proc, command);
        }
        input_buf.clear();
    }

}
