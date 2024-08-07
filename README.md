### Simple FTP Client for High Load Testing

This Rust-based application facilitates high-load testing over the FTP protocol, supporting both plain FTP and FTP with TLS. It offers the flexibility to use active and passive modes, configurable via command-line options. The application allows for generating, uploading, and downloading files to and from an FTP server, making it an excellent tool for stress testing and performance evaluation.

#### Key Features:
- **Flexible FTP Modes:** Choose between active and passive FTP modes through simple command-line options.
- **Secure Connections:** Supports both plain FTP and FTP over TLS for secure data transfers.
- **File Operations:** Generate random text files of specified sizes, upload files to the server, and download files from the server.
- **Command-Line Configuration:** Easily configure server URL, FTP account credentials, file sizes, connection modes, and TLS usage.

#### Command-Line Options:
- `--generate, -g`: Generate a random text file of a specified size.
- `--upload, -u`: Upload a specified file to the FTP server.
- `--download, -d`: Download a specified file from the FTP server.
- `--server, -s`: Specify the FTP server URL.
- `--username, -U`: Specify the FTP account username.
- `--password, -P`: Specify the FTP account password.
- `--size`: Set the size of the file to generate (in bytes).
- `--mode, -m`: Set FTP mode (active/passive).
- `--tls, -t`: Use FTP with TLS for secure connections.
- `--iterations, -i`: Specify the number of iterations for upload/download operations.

#### Example Usage:
```sh
# Generate a 1MB file
ftp_client --generate myfile.txt --size 1048576

# Upload a file to the FTP server in passive mode using plain FTP
ftp_client --upload myfile.txt --server ftp://example.com --username myuser --password mypass --mode passive

# Download a file from the FTP server using FTP with TLS
ftp_client --download myfile.txt --server ftp://example.com --username myuser --password mypass --tls
```

This application is designed to handle high load scenarios, making it a robust tool for performance testing and benchmarking of FTP servers.
