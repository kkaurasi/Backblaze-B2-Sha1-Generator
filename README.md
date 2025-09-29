# Backblaze B2 SHA-1 Generator

A desktop utility (Tkinter GUI) for computing file checksums and generating ready-to-use CLI commands for [Backblaze B2 Cloud Storage](https://www.backblaze.com/b2/cloud-storage.html).

## Features

- Checksum calculator
  - SHA-1 (hex and base64)
  - CRC32 (hex and base64)
  - MD5 (hex and base64)
- File size output in a copyable field
  - Automatically included in CLI examples as `--content-length`
- CLI command generator
  - AWS CLI (`s3api put-object`, `s3 cp`)
  - B2 CLI (`b2 file upload`)
  - Metadata auto-filled with SHA-1, CRC32, and MD5 values
- Region selection dropdown
  - Predefined B2 regions (`us-west-004`, `us-east-005`, etc.)
  - Endpoint automatically updated in CLI examples
- Verification commands
  - `aws s3api get-object` commands to validate uploads
  - Local checksum validation with `openssl` and Python one-liners

## Installation and Usage

### Requirements
- Python 3.8 or newer
- `tkinter` (usually included with Python on macOS/Linux; Windows installs may require it to be enabled)
- boto3>=1.34 + botocore>=1.34

### Running locally
Clone this repository and start the application:

```bash
git clone https://github.com/<YOUR_USERNAME>/Backblaze-B2-Sha1-Generator.git
cd Backblaze-B2-Sha1-Generator/src
python3 sha1_cligenerator_main.py
