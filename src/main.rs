use chrono::NaiveTime;
use clap::Parser;
use parsswd::PwEnt;
use std::default;
use std::fs;
use std::fs::File;
use utmp_rs::UtmpEntry;
use utmp_rs::UtmpParser;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional name to operate on
    #[arg(short, long)]
    long: bool,

    #[arg(short, long = "match")]
    match_: bool,

    #[arg(short, long)]
    plan: bool,

    #[arg(short, long)]
    short: bool,

    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

#[derive(Debug)]
enum Status {
    LastLog,
    LoggedIn,
}

#[derive(Debug)]
struct Where {
    status: Status,
    login_at: chrono::DateTime<chrono::Utc>,
    idle_time: chrono::DateTime<chrono::Utc>,
    tty: String,
    host: String,
    writable: bool,
}

#[derive(Debug)]
struct Person {
    uid: u32,
    dir: String,
    home_phone: String,
    name: String,
    office: String,
    office_phone: String,
    realname: String,
    shell: String,
    mail_read: chrono::DateTime<chrono::Utc>,
    mail_recv: chrono::DateTime<chrono::Utc>,
    where_list: Vec<Where>,
}

impl Person {
    pub fn show_file(&self, name: &str) {
        let path = std::path::Path::new(&self.home_phone).join(name);
        let lstat = match std::fs::symlink_metadata(path) {
            Ok(v) => v,
            Err(_) => return,
        };

        println!("{:?}", lstat)
    }
}

fn get_passwd_entries(passwd: &str) -> Vec<PwEnt<'_>> {
    let mut entries: Vec<PwEnt<'_>> = Vec::new();
    for line in passwd.lines() {
        match PwEnt::from_str(line) {
            Some(e) => entries.push(e),
            None => continue,
        }
    }
    entries
}

fn no_finger(pw_ent: &PwEnt<'_>) -> bool {
    std::path::Path::new(&format!("{}/.nofinger", pw_ent.home_dir)).exists()
}

#[inline]
fn string_or_empty(s: Option<&str>) -> String {
    match s {
        Some(s) => s.to_string(),
        None => "".to_string(),
    }
}

fn pw_ent_to_person(pw_ent: &PwEnt<'_>) -> Person {
    let mut parts = pw_ent.gecos.trim_start_matches('*').split(',');
    let (realname, office, officephone, homephone) =
        (parts.next(), parts.next(), parts.next(), parts.next());
    Person {
        uid: pw_ent.uid,
        dir: pw_ent.home_dir.to_string(),
        home_phone: string_or_empty(homephone),
        name: pw_ent.name.to_string(),
        office: string_or_empty(office),
        office_phone: string_or_empty(officephone),
        realname: string_or_empty(realname),
        shell: pw_ent.shell.to_string(),
        mail_read: chrono::MIN_DATETIME,
        mail_recv: chrono::MIN_DATETIME,
        where_list: Vec::new(),
    }
}

fn pw_ent_to_where(line: &str, host: &str) -> Where {
    Where {
        status: Status::LoggedIn,
        login_at: Default::default(),
        idle_time: Default::default(),
        tty: Default::default(),
        host: host.to_string(),
        writable: Default::default(),
    }
}

fn main() {
    let cli = Cli::parse();
    let passwd = fs::read_to_string("/etc/passwd").unwrap();
    let entries = get_passwd_entries(&passwd);
    let mut persons: Vec<Person> = Vec::new();

    for entry in UtmpParser::from_path("/var/run/utmp").unwrap() {
        let entry = entry.unwrap();
        match entry {
            UtmpEntry::UserProcess {
                pid,
                line,
                user,
                host,
                session,
                time,
            } => {
                println!("pid: {pid}, line: {line}, user: {user},host: {host}, session: {session}, time: {time}");
                let i = match persons.iter().position(|e| e.name == user) {
                    Some(i) => i,
                    None => {
                        let pw_ent = match entries.iter().find(|&e| e.name == user) {
                            Some(e) => e,
                            None => continue,
                        };
                        if no_finger(pw_ent) {
                            continue;
                        }
                        persons.push(pw_ent_to_person(pw_ent));
                        persons.len() - 1
                    }
                };
                persons[i].where_list.push(pw_ent_to_where(&line, &host))
            }
            _ => continue,
        }
        // ...
    }

    for person in persons {
        println!("{:?}\n", person)
    }
}
