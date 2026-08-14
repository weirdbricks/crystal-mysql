require "openssl/sha1"
require "openssl/digest"

module MySql::Protocol
  # CLIENT_PLUGIN_AUTH - see HandshakeResponse41.
  CLIENT_PLUGIN_AUTH = 0x00080000

  struct HandshakeV10
    getter auth_plugin_data : Bytes
    getter charset : UInt8

    # The server's declared default auth plugin (e.g.
    # "mysql_native_password", "caching_sha2_password") - only present
    # when the server sets CLIENT_PLUGIN_AUTH, which every server this
    # driver targets does. Used so the client can declare/compute the
    # matching auth response up front, rather than always assuming
    # mysql_native_password and needing an AuthSwitchRequest round trip
    # whenever the account uses something else (e.g. every MySQL 8+
    # account by default, which uses caching_sha2_password).
    getter auth_plugin_name : String?

    def initialize(@auth_plugin_data, @charset, @auth_plugin_name = nil)
    end

    def self.read(packet : MySql::ReadPacket)
      protocol_version = packet.read_byte!
      version = packet.read_string
      thread = packet.read_int

      auth_data = Bytes.new(20)
      packet.read_fully(auth_data[0, 8])
      packet.read_byte!
      cap1 = packet.read_byte!
      cap2 = packet.read_byte!
      charset = packet.read_byte!
      packet.read_byte_array(2)
      cap3 = packet.read_byte!
      cap4 = packet.read_byte!
      capabilities = cap1.to_u32 | (cap2.to_u32 << 8) | (cap3.to_u32 << 16) | (cap4.to_u32 << 24)

      auth_plugin_data_length = packet.read_byte!
      packet.read_byte_array(10)
      packet.read_fully(auth_data[8, {13, auth_plugin_data_length.to_i16 - 8}.max - 1])
      packet.read_byte!

      auth_plugin_name = packet.read_string if (capabilities & CLIENT_PLUGIN_AUTH) != 0

      HandshakeV10.new(auth_data, charset, auth_plugin_name)
    end
  end

  # Computes the challenge-response auth token for whichever plugin the
  # server actually wants, so the client doesn't have to always guess
  # mysql_native_password and rely on an AuthSwitchRequest round trip for
  # every account that uses something else - notably every MySQL 8+
  # account by default (caching_sha2_password).
  #
  # Both supported plugins use the identical XOR-of-double-hash shape,
  # just with a different hash function and a different concatenation
  # order for the third hash - verified against PyMySQL's own
  # scramble_native_password/scramble_caching_sha2 (the reference
  # implementation every other MySQL client, including real Ansible's own
  # community.mysql, is built on):
  #   mysql_native_password:   SHA1(pw)   XOR SHA1(nonce         + SHA1(SHA1(pw)))
  #   caching_sha2_password:   SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + nonce)
  module Auth
    def self.scramble(plugin_name : String?, password : String, nonce : Bytes) : Bytes
      case plugin_name
      when "caching_sha2_password"
        scramble_sha256(password, nonce)
      when "auth_socket", "unix_socket", "mysql_clear_password"
        # These plugins don't use password-based challenge-response.
        # auth_socket/unix_socket verify peer credentials (SO_PEERCRED
        # on Unix sockets) instead of a password hash. mysql_clear_password
        # sends the plaintext password itself (only over TLS).
        # An empty response tells the server to proceed with its own
        # non-password verification logic.
        Bytes.new(0)
      else
        # mysql_native_password, and the default when the server doesn't
        # declare a plugin at all (pre-4.1-style servers this driver
        # doesn't otherwise support anyway).
        scramble_sha1(password, nonce)
      end
    end

    def self.scramble_sha1(password : String, nonce : Bytes) : Bytes
      p1 = OpenSSL::SHA1.hash(password).to_slice
      p2 = OpenSSL::SHA1.hash(p1.to_unsafe, LibC::SizeT.new(p1.size)).to_slice

      buffer = Bytes.new(nonce.size + p2.size)
      buffer.copy_from(nonce)
      (buffer + nonce.size).copy_from(p2)

      p3 = OpenSSL::SHA1.hash(buffer.to_unsafe, LibC::SizeT.new(buffer.size)).to_slice

      xor(p1, p3)
    end

    def self.scramble_sha256(password : String, nonce : Bytes) : Bytes
      p1 = sha256(password.to_slice)
      p2 = sha256(p1)

      buffer = Bytes.new(p2.size + nonce.size)
      buffer.copy_from(p2)
      (buffer + p2.size).copy_from(nonce)

      p3 = sha256(buffer)

      xor(p1, p3)
    end

    def self.sha256(data : Bytes) : Bytes
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(data)
      digest.final
    end

    private def self.xor(a : Bytes, b : Bytes) : Bytes
      Bytes.new(a.size) { |i| a[i] ^ b[i] }
    end
  end

  # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html#sect_protocol_connection_phase_packets_protocol_handshake_response41
  struct HandshakeResponse41
    CLIENT_LONG_PASSWORD                  = 0x00000001
    CLIENT_FOUND_ROWS                     = 0x00000002
    CLIENT_LONG_FLAG                      = 0x00000004
    CLIENT_CONNECT_WITH_DB                = 0x00000008
    CLIENT_NO_SCHEMA                      = 0x00000010
    CLIENT_COMPRESS                       = 0x00000020
    CLIENT_ODBC                           = 0x00000040
    CLIENT_LOCAL_FILES                    = 0x00000080
    CLIENT_IGNORE_SPACE                   = 0x00000100
    CLIENT_PROTOCOL_41                    = 0x00000200
    CLIENT_INTERACTIVE                    = 0x00000400
    CLIENT_SSL                            = 0x00000800
    CLIENT_IGNORE_SIGPIPE                 = 0x00001000
    CLIENT_TRANSACTIONS                   = 0x00002000
    CLIENT_RESERVED                       = 0x00004000
    CLIENT_SECURE_CONNECTION              = 0x00008000
    CLIENT_MULTI_STATEMENTS               = 0x00010000
    CLIENT_MULTI_RESULTS                  = 0x00020000
    CLIENT_PS_MULTI_RESULTS               = 0x00040000
    CLIENT_PLUGIN_AUTH                    = 0x00080000
    CLIENT_CONNECT_ATTRS                  = 0x00100000
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   = 0x00400000
    CLIENT_SESSION_TRACK                  = 0x00800000
    CLIENT_DEPRECATE_EOF                  = 0x01000000

    # auth_plugin_name - the server's declared default plugin (HandshakeV10
    # #auth_plugin_name), so the auth response matches what the account
    # actually needs instead of always assuming mysql_native_password.
    def initialize(@username : String?, @password : String?, @initial_catalog : String?, @auth_plugin_data : Bytes, @charset : UInt8, @auth_plugin_name : String? = nil)
    end

    # The full capability set both write_ssl_request and write declare -
    # some servers hold the client to whatever it announced in the
    # SSLRequest for the rest of the connection, so a reduced subset
    # there (as this used to declare: just CLIENT_PROTOCOL_41 | CLIENT_SSL)
    # can get the real handshake response's own auth plugin data rejected
    # afterward with "Client does not support authentication protocol
    # requested by server" - reproduced against real MySQL 8 and MariaDB,
    # fixed by declaring the identical capability set in both packets.
    private def capabilities : Int32
      caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
      caps |= CLIENT_PLUGIN_AUTH
      caps |= CLIENT_CONNECT_WITH_DB if @initial_catalog
      caps
    end

    # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html
    def write_ssl_request(packet : MySql::WritePacket)
      caps = capabilities | CLIENT_SSL

      packet.write_bytes caps, IO::ByteFormat::LittleEndian

      packet.write_bytes 0x00000000u32, IO::ByteFormat::LittleEndian
      packet.write_byte @charset
      23.times { packet.write_byte 0_u8 }
    end

    def write(packet : MySql::WritePacket)
      caps = capabilities

      packet.write_bytes caps, IO::ByteFormat::LittleEndian

      packet.write_bytes 0x00000000u32, IO::ByteFormat::LittleEndian
      packet.write_byte @charset
      23.times { packet.write_byte 0_u8 }

      packet << @username
      packet.write_byte 0_u8

      if password = @password
        auth_response = Auth.scramble(@auth_plugin_name, password, @auth_plugin_data)

        packet.write_lenenc_int auth_response.size
        packet.write(auth_response)
      else
        packet.write_byte 0_u8
      end

      if initial_catalog = @initial_catalog
        packet << initial_catalog
        packet.write_byte 0_u8
      end

      if @password
        packet << (@auth_plugin_name || "mysql_native_password")
        packet.write_byte 0_u8
      elsif @username
        # When no password is given but the server still expects a plugin
        # name (CLIENT_PLUGIN_AUTH is now advertised unconditionally),
        # send the server's declared plugin name so it knows what the
        # client expects. This is load-bearing for auth_socket/unix_socket
        # accounts: the server uses it to decide the auth flow.
        packet << (@auth_plugin_name || "mysql_native_password")
        packet.write_byte 0_u8
      end
    end
  end

  struct Quit
    def write(packet : MySql::WritePacket)
      packet.write_byte 1_u8
    end
  end

  # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_request.html
  # Sent by the server (status byte 0xFE, after the initial handshake
  # response) when the account needs a different auth plugin than the one
  # the client declared - each with its own new nonce, since the fast-path
  # response above already tries to match the server's originally
  # declared plugin, this is mostly a fallback for accounts whose plugin
  # differs from the server's overall default.
  struct AuthSwitchRequest
    getter plugin_name : String
    getter auth_plugin_data : Bytes

    def initialize(@plugin_name, @auth_plugin_data)
    end

    def self.read(packet : MySql::ReadPacket)
      plugin_name = packet.read_string
      # Whatever's left in the packet is the new nonce - trailing NUL (if
      # any) included is harmless, since the scramble functions only use
      # exactly the first bytes of this per algorithm; MySQL/MariaDB always
      # send exactly 20 bytes here in practice for both plugins this
      # driver supports.
      data = Bytes.new(20)
      packet.read_fully(data)
      AuthSwitchRequest.new(plugin_name, data)
    end
  end
end
