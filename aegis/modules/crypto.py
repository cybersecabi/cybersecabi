import click
import hashlib
import base64
import binascii
import string
import itertools
from typing import Optional
from aegis.core import output_result, Spinner, log_activity

class CryptoTools:
    @staticmethod
    def hash_string(data: str, algorithm: str = 'md5') -> str:
        """Generate hash of string"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha384': hashlib.sha384,
            'blake2b': hashlib.blake2b,
        }
        
        if algorithm in algorithms:
            return algorithms[algorithm](data.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def hash_file(filepath: str, algorithm: str = 'sha256') -> str:
        """Generate hash of file"""
        hash_obj = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(data: str) -> str:
        return base64.b64decode(data.encode()).decode()
    
    @staticmethod
    def encode_hex(data: str) -> str:
        return binascii.hexlify(data.encode()).decode()
    
    @staticmethod
    def decode_hex(data: str) -> str:
        return binascii.unhexlify(data.encode()).decode()
    
    @staticmethod
    def rot13(text: str) -> str:
        return text.translate(str.maketrans(
            string.ascii_uppercase + string.ascii_lowercase,
            string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
            string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
        ))
    
    @staticmethod
    def caesar_cipher(text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def xor_encrypt(data: str, key: str) -> str:
        result = []
        for i, char in enumerate(data):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return ''.join(result)
    
    @staticmethod
    def crack_hash(hash_value: str, wordlist: list) -> Optional[str]:
        """Simple hash cracking with wordlist"""
        for word in wordlist:
            for algo in ['md5', 'sha1', 'sha256']:
                if CryptoTools.hash_string(word, algo) == hash_value.lower():
                    return word
        return None

@click.group()
def crypto_group():
    """Cryptographic tools and hash utilities"""
    pass

@crypto_group.command()
@click.option('--text', '-t', required=True, help='Text to hash')
@click.option('--algorithm', '-a', default='sha256', 
              type=click.Choice(['md5', 'sha1', 'sha256', 'sha512', 'sha384', 'blake2b']),
              help='Hash algorithm')
def hash(text, algorithm):
    """Generate hash from text"""
    result = CryptoTools.hash_string(text, algorithm)
    click.echo(f"\n[cyan]{algorithm.upper()} Hash:[/cyan]")
    click.echo(f"  Input: {text}")
    click.echo(f"  Hash:  {result}")

@crypto_group.command()
@click.option('--filepath', '-f', required=True, help='File to hash', type=click.Path(exists=True))
@click.option('--algorithm', '-a', default='sha256',
              type=click.Choice(['md5', 'sha1', 'sha256', 'sha512', 'sha384']),
              help='Hash algorithm')
def filehash(filepath, algorithm):
    """Generate hash of file"""
    with Spinner("Hashing file..."):
        result = CryptoTools.hash_file(filepath, algorithm)
    
    click.echo(f"\n[cyan]{algorithm.upper()} Hash:[/cyan]")
    click.echo(f"  File: {filepath}")
    click.echo(f"  Hash: {result}")

@crypto_group.command()
@click.option('--text', '-t', required=True, help='Text to encode/decode')
@click.option('--decode', '-d', is_flag=True, help='Decode instead of encode')
@click.option('--format', '-f', 'fmt', default='base64',
              type=click.Choice(['base64', 'base32', 'hex', 'url']),
              help='Encoding format')
def encode(text, decode, fmt):
    """Encode/decode text using various algorithms"""
    import urllib.parse
    
    if decode:
        if fmt == 'base64':
            result = CryptoTools.decode_base64(text)
        elif fmt == 'base32':
            result = base64.b32decode(text.encode()).decode()
        elif fmt == 'hex':
            result = CryptoTools.decode_hex(text)
        elif fmt == 'url':
            result = urllib.parse.unquote(text)
    else:
        if fmt == 'base64':
            result = CryptoTools.encode_base64(text)
        elif fmt == 'base32':
            result = base64.b32encode(text.encode()).decode()
        elif fmt == 'hex':
            result = CryptoTools.encode_hex(text)
        elif fmt == 'url':
            result = urllib.parse.quote(text)
    
    action = "Decoded" if decode else "Encoded"
    click.echo(f"\n[cyan]{action} ({fmt}):[/cyan]")
    click.echo(f"  Input:  {text}")
    click.echo(f"  Output: {result}")

@crypto_group.command()
@click.option('--text', '-t', required=True, help='Text to encrypt/decrypt')
@click.option('--shift', '-s', type=int, default=13, help='Shift value (default: 13 for ROT13)')
@click.option('--decrypt', '-d', is_flag=True, help='Decrypt instead of encrypt')
def caesar(text, shift, decrypt):
    """Caesar cipher encryption/decryption"""
    if decrypt:
        shift = -shift
    
    result = CryptoTools.caesar_cipher(text, shift)
    
    action = "Decrypted" if decrypt else "Encrypted"
    click.echo(f"\n[cyan]Caesar Cipher ({action}):[/cyan]")
    click.echo(f"  Input:  {text}")
    click.echo(f"  Shift:  {abs(shift)}")
    click.echo(f"  Output: {result}")

@crypto_group.command()
@click.option('--text', '-t', required=True, help='Text to process')
@click.option('--key', '-k', required=True, help='XOR key')
def xor(text, key):
    """XOR encryption/decryption"""
    result = CryptoTools.xor_encrypt(text, key)
    
    click.echo(f"\n[cyan]XOR Operation:[/cyan]")
    click.echo(f"  Input:  {text}")
    click.echo(f"  Key:    {key}")
    click.echo(f"  Output: {binascii.hexlify(result.encode()).decode()}")

@crypto_group.command()
@click.option('--hash', '-h', 'hash_value', required=True, help='Hash to crack')
@click.option('--wordlist', '-w', help='Path to wordlist file')
def crack(hash_value, wordlist):
    """Attempt to crack hash with wordlist"""
    log_activity('crypto', f"Attempting to crack hash: {hash_value[:20]}...")
    
    # Default wordlist
    default_words = ['password', '123456', 'admin', 'root', 'qwerty', 'letmein',
                     'welcome', 'monkey', 'dragon', 'master', 'hello123']
    
    words = default_words
    if wordlist:
        with open(wordlist, 'r') as f:
            words = [line.strip() for line in f]
    
    with Spinner("Cracking hash..."):
        result = CryptoTools.crack_hash(hash_value, words)
    
    if result:
        click.echo(f"\n[green]✓ Hash cracked: {result}[/green]")
    else:
        click.echo(f"\n[red]✗ Hash not found in wordlist[/red]")

@crypto_group.command()
@click.option('--hash1', '-a', required=True, help='First hash')
@click.option('--hash2', '-b', required=True, help='Second hash')
def compare(hash1, hash2):
    """Compare two hashes for equality"""
    match = hash1.lower() == hash2.lower()
    
    if match:
        click.echo("[green]✓ Hashes match[/green]")
    else:
        click.echo("[red]✗ Hashes do not match[/red]")
