import pytest
from aegis.modules.crypto import CryptoTools
from aegis.modules.recon import PortScanner

def test_crypto_hash():
    """Test hash generation"""
    result = CryptoTools.hash_string("test", "md5")
    assert len(result) == 32
    assert result == "098f6bcd4621d373cade4e832627b4f6"

def test_crypto_base64():
    """Test base64 encoding/decoding"""
    original = "Hello, World!"
    encoded = CryptoTools.encode_base64(original)
    decoded = CryptoTools.decode_base64(encoded)
    assert decoded == original

def test_crypto_rot13():
    """Test ROT13 encoding"""
    result = CryptoTools.rot13("Hello")
    assert result == "Uryyb"

def test_port_scanner_init():
    """Test port scanner initialization"""
    scanner = PortScanner(timeout=2.0, threads=50)
    assert scanner.timeout == 2.0
    assert scanner.threads == 50

def test_caesar_cipher():
    """Test Caesar cipher"""
    text = "ABC"
    encrypted = CryptoTools.caesar_cipher(text, 3)
    assert encrypted == "DEF"
    decrypted = CryptoTools.caesar_cipher(encrypted, -3)
    assert decrypted == text
