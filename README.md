# JWTHunter

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)

**JWTHunter** is a powerful JWT (JSON Web Token) testing tool designed for security researchers and bug bounty hunters to identify and exploit common JWT vulnerabilities.

## Overview

JSON Web Tokens (JWTs) are widely used for authentication and session management in modern web applications. Unfortunately, many JWT implementations contain vulnerabilities that can lead to authentication bypasses and privilege escalation. JWTHunter helps security researchers identify and demonstrate these vulnerabilities in a controlled environment.

## Features

- **Multiple Exploitation Methods:**
  - `jwk` header injection (embeds forged key material directly in the token)
  - `jku` header injection (points verification to an attacker-controlled URL)
 
- **Customizable Payloads:**
  - Modify claims to test privilege escalation
  - Change user roles and permissions
  - Test authorization boundaries

- **PortSwigger Lab Compatible:**
  - Specially optimized for PortSwigger Web Security Academy labs
  - Detailed step-by-step instructions for solving lab challenges

- **Comprehensive Output:**
  - Debug information for original and modified tokens
  - Generated JWK and JWK Sets
  - Example curl commands for testing

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/jwthunter.git
cd jwthunter

# Install requirements
pip install -r requirements.txt
```

### Requirements
- Python 3.6+
- cryptography

## Usage

### Basic Usage:

```bash
python jwthunter.py --jwt "eyJhbGciOiJSUzI..." --method jwk
```

### JKU Header Injection:

```bash
python jwthunter.py --jwt "eyJhbGciOiJSUzI..." --method jku --jku-url "https://your-server.com/jwks.json"
```

### Custom Payload:

```bash
python jwthunter.py --jwt "eyJhbGciOiJSUzI..." --method jwk --payload '{"sub":"admin","role":"admin"}'
```

### PortSwigger Labs:

```bash
python jwthunter.py --jwt "eyJhbGciOiJSUzI..." --method jku --jku-url "https://exploit-server.net/exploit.json" --portswigger
```

## For PortSwigger Web Security Academy Labs

### JWT authentication bypass via jku header injection:

1. Get a valid JWT from the lab application
2. Run JWTHunter with the jku method:
   ```
   python jwthunter.py --jwt "your_token" --method jku --jku-url "https://your-exploit-server.net/exploit.json" --portswigger
   ```
3. Copy the JWK Set JSON to your Exploit Server
4. Set the filename to `exploit.json`
5. Make sure Content-Type is set to `application/json`
6. Store and view the exploit to verify it works
7. Use the modified token to access admin resources

### JWT authentication bypass via jwk header injection:

1. Get a valid JWT from the lab application
2. Run JWTHunter with the jwk method:
   ```
   python jwthunter.py --jwt "your_token" --method jwk --portswigger
   ```
3. Use the generated token to access admin resources

## Upcoming Features

- Algorithm confusion attack (`alg: none` and RS256/HS256 confusion)
- Key ID (kid) parameter injection attacks
- JWT signature validation bypass via x5c header injection
- Support for cracking weak JWT secrets

## Ethical Use & Disclaimer

This tool is provided for educational and professional security testing purposes only. Use it only on applications you own or have explicit permission to test. Unauthorized testing of systems is illegal and unethical.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by vulnerabilities documented by PortSwigger Web Security Academy
- Created for security professionals conducting authorized bug bounty testing
