require "base64"
require "random/secure"
require "big"
require "openssl"

module MySql
  # RSA-OAEP encryption of a password against a server's public key, for
  # caching_sha2_password's full-authentication sub-protocol over a plain
  # (unencrypted) connection: the client asks for the server's public key,
  # RSA-OAEP encrypts the scrambled password with it, and only the
  # ciphertext crosses the wire.
  #
  # Implemented in plain Crystal (GMP bignums from `big`, SHA-1 from
  # `openssl`) rather than through EVP_PKEY calls on purpose: this shard is
  # compiled into binaries that already declare their own libcrypto `fun`s
  # (the same C symbol can't be declared twice in one binary), so pulling
  # PEM/EVP_PKEY bindings in here would clash with the host program's own.
  module RsaOaep
    extend self

    HASH_LEN = 20

    class Error < Exception; end

    # Encrypts *plaintext* with the RSA public key in *pem*, OAEP padding
    # with SHA-1 and an empty label (what MySQL's server-side
    # caching_sha2_password full auth expects), and returns the ciphertext
    # as a big-endian byte string exactly as wide as the modulus.
    def encrypt(pem : Bytes | String, plaintext : Bytes) : Bytes
      modulus, exponent = public_key(pem)
      k = (modulus.bit_length + 7) // 8
      em = oaep_encode(plaintext, k)

      encrypted = BigInt.new(chars_hex(em), 16)** exponent % modulus
      chars_hex_bytes(encrypted.to_s(16).rjust(k * 2, '0'))
    end

    private def oaep_encode(message : Bytes, k : Int32) : Bytes
      m_len = message.size
      if k < 2 * HASH_LEN + 2 || m_len > k - 2 * HASH_LEN - 2
        raise Error.new("message too long for RSA-OAEP with a #{k}-byte modulus")
      end

      l_hash = sha1(Bytes.empty)
      db = l_hash + Bytes.new(k - m_len - 2 * HASH_LEN - 2) + Bytes[0x01_u8] + message
      seed = Bytes.new(HASH_LEN) { Random::Secure.rand(256).to_u8 }
      masked_db = xor(db, mgf1(seed, db.size))
      masked_seed = xor(seed, mgf1(masked_db, HASH_LEN))

      Bytes[0x00] + masked_seed + masked_db
    end

    private def mgf1(seed : Bytes, length : Int32) : Bytes
      out = Bytes.new(0)
      counter = 0_u32
      while out.size < length
        out += sha1(seed + counter_bytes(counter))
        counter += 1
      end
      out[0, length]
    end

    private def counter_bytes(counter : UInt32) : Bytes
      Bytes.new(4) { |i| (counter >> (24 - 8 * i)).to_u8 }
    end

    # OpenSSL::Digest rather than OpenSSL::SHA1: the latter's one-shot
    # helper resolves a `class` method on its argument, which breaks inside
    # binaries that declare libcrypto's SHA1 under a different lib name.
    private def sha1(data : Bytes) : Bytes
      digest = OpenSSL::Digest.new("SHA1")
      digest.update(data)
      digest.final
    end

    private def xor(a : Bytes, b : Bytes) : Bytes
      Bytes.new(a.size) { |i| a[i] ^ b[i] }
    end

    # Minimal DER walker - just enough to pull an RSA (n, e) pair out of
    # either a SubjectPublicKeyInfo ("BEGIN PUBLIC KEY", what MySQL sends)
    # or a bare PKCS#1 RSAPublicKey ("BEGIN RSA PUBLIC KEY").
    private def public_key(pem : Bytes | String) : {BigInt, BigInt}
      body = pem_body(pem)
      offset = 0
      outer = read_tlv(body, offset)
      raise Error.new("public key is not a DER SEQUENCE") unless outer[0] == 0x30

      content = outer[2]
      offset = 0
      if read_tlv(content, 0)[0] == 0x30
        # SubjectPublicKeyInfo: skip the AlgorithmIdentifier, unwrap the
        # subjectPublicKey BIT STRING's payload.
        read_tlv(content, 0)
        bits = read_tlv(content, element_end(content, 0))
        raise Error.new("public key is not a DER BIT STRING") unless bits[0] == 0x03
        inner = bits[2][1, bits[2].size - 1]
        sequence = read_tlv(inner, 0)
        raise Error.new("public key is not a DER SEQUENCE") unless sequence[0] == 0x30
        content = sequence[2]
        offset = 0
      end

      n = read_tlv(content, offset)
      e = read_tlv(content, element_end(content, offset))
      raise Error.new("public key is not an RSA key") unless n[0] == 0x02 && e[0] == 0x02
      {unsigned(n[2]), unsigned(e[2])}
    end

    # {tag, content-size, content} of the DER element at *offset*.
    private def read_tlv(data : Bytes, offset : Int32) : {UInt8, Int32, Bytes}
      tag = data[offset].to_u8
      header = header_size(data[offset + 1].to_i)
      size = content_size(data, offset)
      {tag, size, data[(offset + header), size]}
    end

    # Offset just past the DER element at *offset* - how the next sibling
    # is found (the algorithm identifier before the key bit string).
    private def element_end(data : Bytes, offset : Int32) : Int32
      offset + header_size(data[offset + 1].to_i) + content_size(data, offset)
    end

    private def header_size(raw_size : Int32) : Int32
      (raw_size & 0x80) == 0 ? 2 : 2 + (raw_size & 0x7f)
    end

    private def content_size(data : Bytes, offset : Int32) : Int32
      raw_size = data[offset + 1].to_i
      return raw_size if (raw_size & 0x80) == 0

      size = 0
      (raw_size & 0x7f).times { |i| size = (size << 8) | data[offset + 2 + i].to_i }
      size
    end

    private def unsigned(bytes : Bytes) : BigInt
      BigInt.new(chars_hex(bytes), 16)
    end

    private def chars_hex(bytes : Bytes) : String
      String.build(bytes.size * 2) { |io| bytes.each { |b| io << "0123456789abcdef"[b >> 4] << "0123456789abcdef"[b & 0x0f] } }
    end

    private def chars_hex_bytes(hex : String) : Bytes
      Bytes.new(hex.size // 2) { |i| hex[i * 2, 2].to_i(16).to_u8 }
    end

    private def pem_body(pem : Bytes | String) : Bytes
      text = pem.is_a?(String) ? pem : String.new(pem, invalid: :skip)
      encoded = text.lines
                        .reject { |line| line.starts_with?("-----") }
                        .join
                        .gsub(/[^A-Za-z0-9+\/=]/, "")
      raise Error.new("public key is not PEM") if encoded.empty?
      Base64.decode(encoded)
    end
  end
end
