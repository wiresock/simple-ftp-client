use chrono::Local;
use clap::{Arg, Command};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use suppaftp::native_tls::{Error as TlsError, TlsConnector};
use suppaftp::types::FileType;
use suppaftp::{
    FtpError as SuppaFtpError, FtpStream as ImplFtpStream, NativeTlsConnector, NativeTlsFtpStream,
};
use thiserror::Error;

// Define a custom error type
#[derive(Error, Debug)]
pub enum FtpError {
    #[error("FTP error")]
    Ftp(#[from] SuppaFtpError),

    #[error("IO error")]
    Io(#[from] io::Error),

    #[error("TLS error")]
    Tls(#[from] TlsError),
}

fn generate_random_text_file(filename: &Path, size: usize) -> io::Result<String> {
    if filename.exists() && filename.metadata()?.len() as usize == size {
        println!(
            "File: {:?} already exists with the correct size of {} bytes.",
            filename, size
        );
        return Ok(hex::encode(Sha256::digest(&std::fs::read(filename)?)));
    }

    let mut file = File::create(filename)?;
    let mut generated_size = 0;
    let block_size = 1024;
    let mut hasher = Sha256::new();

    while generated_size < size {
        let remaining = size - generated_size;
        let chunk_size = std::cmp::min(block_size, remaining);
        let block: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(chunk_size)
            .map(char::from)
            .collect();

        let block_bytes = block.as_bytes();
        file.write_all(block_bytes)?;
        hasher.update(block_bytes);
        generated_size += chunk_size;
    }

    println!("Generated file: {:?}", filename);
    Ok(hex::encode(hasher.finalize()))
}

fn upload_file_non_tls(
    server_url: &str,
    username: Option<&String>,
    password: Option<&String>,
    filename: &Path,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ftp_stream = ImplFtpStream::connect((server_url, 21))?;
    if let Some(username) = username {
        let default_password = String::from("");
        let password = password.unwrap_or(&default_password);
        ftp_stream.login(username, password)?;
    } else {
        ftp_stream.login("anonymous", "")?;
    }

    match mode {
        "active" => ftp_stream = ftp_stream.active_mode(Duration::from_secs(10)),
        "passive" => ftp_stream.set_mode(suppaftp::types::Mode::Passive),
        _ => return Err(Box::from("Invalid mode. Use 'active' or 'passive'.")),
    }

    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    ftp_stream.put_file(filename.to_str().unwrap(), &mut &buffer[..])?;
    ftp_stream.quit()?;
    Ok(())
}

fn upload_file_tls(
    server_url: &str,
    username: Option<&String>,
    password: Option<&String>,
    filename: &Path,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ftp_stream = NativeTlsFtpStream::connect((server_url, 21))?;
    let tls_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    let tls_connector = NativeTlsConnector::from(tls_connector);
    let mut ftp_stream = ftp_stream.into_secure(tls_connector, server_url)?;
    if let Some(username) = username {
        let default_password = String::from("");
        let password = password.unwrap_or(&default_password);
        ftp_stream.login(username, password)?;
    } else {
        ftp_stream.login("anonymous", "")?;
    }
    ftp_stream.transfer_type(FileType::Binary)?;
    match mode {
        "active" => ftp_stream = ftp_stream.active_mode(Duration::from_secs(10)),
        "passive" => ftp_stream.set_mode(suppaftp::types::Mode::Passive),
        _ => return Err(Box::from("Invalid mode. Use 'active' or 'passive'.")),
    }
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    ftp_stream.put_file(filename.to_str().unwrap(), &mut &buffer[..])?;
    ftp_stream.quit()?;
    Ok(())
}

fn download_file_non_tls(
    server_url: &str,
    username: Option<&String>,
    password: Option<&String>,
    filename: &str,
    mode: &str,
) -> Result<(usize, String), FtpError> {
    let mut ftp_stream = ImplFtpStream::connect((server_url, 21))?;
    if let Some(username) = username {
        let default_password = String::from("");
        let password = password.unwrap_or(&default_password);
        ftp_stream.login(username, password)?;
    } else {
        ftp_stream.login("anonymous", "")?;
    }

    match mode {
        "active" => ftp_stream = ftp_stream.active_mode(Duration::from_secs(10)),
        "passive" => ftp_stream.set_mode(suppaftp::types::Mode::Passive),
        _ => {
            return Err(FtpError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid mode. Use 'active' or 'passive'.",
            )))
        }
    }

    let mut reader = ftp_stream.retr_as_buffer(filename)?;
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    ftp_stream.quit()?;
    let mut hasher = Sha256::new();
    hasher.update(&buffer);

    Ok((buffer.len(), hex::encode(hasher.finalize())))
}

fn download_file_tls(
    server_url: &str,
    username: Option<&String>,
    password: Option<&String>,
    filename: &str,
    mode: &str,
) -> Result<(usize, String), FtpError> {
    let ftp_stream = NativeTlsFtpStream::connect((server_url, 21))?;
    let tls_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    let tls_connector = NativeTlsConnector::from(tls_connector);
    let mut ftp_stream = ftp_stream.into_secure(tls_connector, server_url)?;
    if let Some(username) = username {
        let default_password = String::from("");
        let password = password.unwrap_or(&default_password);
        ftp_stream.login(username, password)?;
    } else {
        ftp_stream.login("anonymous", "")?;
    }
    ftp_stream.transfer_type(FileType::Binary)?;
    match mode {
        "active" => ftp_stream = ftp_stream.active_mode(Duration::from_secs(10)),
        "passive" => ftp_stream.set_mode(suppaftp::types::Mode::Passive),
        _ => {
            return Err(FtpError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid mode. Use 'active' or 'passive'.",
            )))
        }
    }
    let mut reader = ftp_stream.retr_as_buffer(filename)?;
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    ftp_stream.quit()?;
    let mut hasher = Sha256::new();
    hasher.update(&buffer);

    Ok((buffer.len(), hex::encode(hasher.finalize())))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("FTP Load Tester")
        .version("1.0")
        .author("Vadim Smirnov <vadim@ntkernel.com>")
        .about("Handles file operations with an FTP server")
        .arg(
            Arg::new("generate")
                .long("generate")
                .short('g')
                .value_name("FILE")
                .help("Generates a file of specified size"),
        )
        .arg(
            Arg::new("upload")
                .long("upload")
                .short('u')
                .value_name("FILE")
                .help("Uploads the specified file"),
        )
        .arg(
            Arg::new("download")
                .long("download")
                .short('d')
                .value_name("FILE")
                .help("Downloads the specified file"),
        )
        .arg(
            Arg::new("server")
                .long("server")
                .short('s')
                .value_name("URL")
                .help("Sets the server URL")
                .required(false),
        )
        .arg(
            Arg::new("username")
                .long("username")
                .short('U')
                .value_name("USERNAME")
                .help("Sets the FTP username")
                .required(false),
        )
        .arg(
            Arg::new("password")
                .long("password")
                .short('P')
                .value_name("PASSWORD")
                .help("Sets the FTP password")
                .required(false),
        )
        .arg(
            Arg::new("size")
                .long("size")
                .value_name("SIZE")
                .help("Sets the file size for generation"),
        )
        .arg(
            Arg::new("tls")
                .long("tls")
                .short('t')
                .help("Use FTP with TLS")
                .action(clap::ArgAction::SetTrue)
                .default_value("false"),
        )
        .arg(
            Arg::new("iterations")
                .long("iterations")
                .short('i')
                .value_name("NUMBER")
                .help("Specifies the number of iterations for upload/download")
                .default_value("1"),
        ) // Default to 1 iteration
        .arg(
            Arg::new("mode")
                .long("mode")
                .short('m')
                .value_name("MODE")
                .help("Sets the FTP mode (active/passive)")
                .required(false)
                .default_value("passive"),
        )
        .get_matches();

    if !matches.args_present() {
        println!("No arguments provided. Use --help for usage information.");
        return Ok(());
    }

    if let Some(file) = matches.get_one::<String>("generate") {
        let size = matches
            .get_one::<String>("size")
            .map(|s| s.parse().unwrap())
            .unwrap_or(1024);
        let path = Path::new(file);
        match generate_random_text_file(path, size) {
            Ok(hash) => println!("SHA256: {}", hash),
            Err(e) => eprintln!("Error: {}", e),
        }
    } else {
        let server_url = matches.get_one::<String>("server").unwrap();
        let username = matches.get_one::<String>("username");
        let password = matches.get_one::<String>("password");
        let iterations = matches
            .get_one::<String>("iterations")
            .and_then(|it| it.parse::<usize>().ok())
            .unwrap_or(1);
        let mode = matches.get_one::<String>("mode").unwrap();
        for _ in 0..iterations {
            // Check if upload is specified
            if let Some(file) = matches.get_one::<String>("upload") {
                println!("{} - Start uploading file: {}", Local::now(), file);
                if matches.get_one::<bool>("tls").copied().unwrap_or(false) {
                    match upload_file_tls(server_url, username, password, Path::new(file), mode) {
                        Ok(_) => println!("{} - Uploaded: {}", Local::now(), file),
                        Err(e) => {
                            eprintln!("{} - Error uploading file {}: {}", Local::now(), file, e)
                        }
                    }
                } else {
                    match upload_file_non_tls(server_url, username, password, Path::new(file), mode)
                    {
                        Ok(_) => println!("{} - Uploaded: {}", Local::now(), file),
                        Err(e) => {
                            eprintln!("{} - Error uploading file {}: {}", Local::now(), file, e)
                        }
                    }
                }
            }

            // Check if download is specified
            if let Some(file) = matches.get_one::<String>("download") {
                println!("{} - Start downloading file: {}", Local::now(), file);
                if matches.get_one::<bool>("tls").copied().unwrap_or(false) {
                    match download_file_tls(server_url, username, password, file, mode) {
                        Ok((size, hash)) => println!(
                            "{} - {}: Downloaded. Size = {} bytes SHA256: {}",
                            Local::now(),
                            file,
                            size,
                            hash
                        ),
                        Err(e) => {
                            eprintln!("{} - Error downloading file {}: {}", Local::now(), file, e)
                        }
                    }
                } else {
                    match download_file_non_tls(server_url, username, password, file, mode) {
                        Ok((size, hash)) => println!(
                            "{} - {}: Downloaded. Size = {} bytes SHA256: {}",
                            Local::now(),
                            file,
                            size,
                            hash
                        ),
                        Err(e) => {
                            eprintln!("{} - Error downloading file {}: {}", Local::now(), file, e)
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
