use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::net::TcpStream;
use encoding_rs_io::DecodeReaderBytesBuilder;
use structopt::StructOpt;
use ipnetwork::IpNetwork;
use indicatif::{ProgressBar, ProgressStyle};
use chrono::{DateTime, Utc};
use csv::Writer;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use futures::future;

// Command line arguments
#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(short = "f", long = "file", help = "Input file with the IP list")]
    file: Option<String>,

    #[structopt(short = "q", long = "quick", help = "Perform a 'quick' whois lookup")]
    quick: bool,

    #[structopt(short = "h", long = "help", help = "Display help information")]
    help: bool,

    #[structopt(short = "o", long = "output", default_value = "whois_results.csv", help = "Output CSV file")]
    output: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opt = Opt::from_args();

    if opt.file.is_none() && !opt.help {
        eprintln!("Please provide a file with the IP list using the -f or --file option");
        std::process::exit(1);
    }
    
    if opt.help {
        println!("Usage: walrus -f [file] -q [quick lookup] -o [output file]  -h [help]");
        return Ok(());
    }
    
    let file = File::open(opt.file.unwrap())?;

    // print ASCII art banner
    println!("BBBBB    OOOOO    XXXXX");
    println!("BB   B  OO   OO    XXX ");
    println!("BBBBB  OO     OO    X  ");
    println!("BB   B  OO   OO    XXX ");
    println!("BBBBB    OOOOO    XXXXX");
    // print date
    let now: DateTime<Utc> = Utc::now();
    println!("=======================");
    println!("Date: {}", now);
    println!("=======================");
    println!("");
    println!("Starting whois lookup...");

    let reader = BufReader::new(DecodeReaderBytesBuilder::new().build(file));
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    let pb = ProgressBar::new(lines.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-"));

        let mut tasks = vec![];
    let wtr = Arc::new(Mutex::new(Writer::from_path(&opt.output).unwrap()));
    let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrency

    {
        let mut wtr = wtr.lock().await;
        wtr.write_record(&["IP", "Whois Result"])?;
    }

    for line in lines {
        let pb = pb.clone();
        let line = line.clone();
        let quick = opt.quick;
        let wtr = Arc::clone(&wtr);
        let permit = Arc::clone(&semaphore).acquire_owned().await;

        tasks.push(tokio::spawn(async move {
            if quick {
                // In quick mode, we just make a whois lookup for a single IP in the CIDR range
                if let Ok(ip_network) = line.parse::<IpNetwork>() {
                    let ip = ip_network.ip();
                    let result = whois_lookup(&ip.to_string()).await.unwrap();
                    let mut wtr = wtr.lock().await;
                    wtr.write_record(&[ip.to_string(), result]).unwrap();
                } else {
                    let result = whois_lookup(&line).await.unwrap();
                    let mut wtr = wtr.lock().await;
                    wtr.write_record(&[line.clone(), result]).unwrap();
                }
            } else {
                // In normal mode, we iterate through every IP in the CIDR range
                if let Ok(ip_network) = line.parse::<IpNetwork>() {
                    for ip in ip_network.iter() {
                        let result = whois_lookup(&ip.to_string()).await.unwrap();
                        let mut wtr = wtr.lock().await;
                        wtr.write_record(&[ip.to_string(), result]).unwrap();
                    }
                } else {
                    let result = whois_lookup(&line).await.unwrap();
                    let mut wtr = wtr.lock().await;
                    wtr.write_record(&[line.clone(), result]).unwrap();
                }
            }
            pb.inc(1);
            drop(permit); // Release the semaphore
        }));
    }

    future::join_all(tasks).await;

    pb.finish_with_message("done");

    Ok(())
}
    
    async fn whois_lookup(ip: &str) -> io::Result<String> {
        let mut stream = TcpStream::connect("whois.cymru.com:43")?;
        stream.write_all(format!("{}\r\n", ip).as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
    
        Ok(String::from_utf8_lossy(&response).replace("\n", " ").to_string())
    }
    
