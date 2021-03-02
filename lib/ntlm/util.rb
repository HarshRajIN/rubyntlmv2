# vim: set et sw=2 sts=2:

require 'base64'
require 'openssl'
require 'openssl/digest'
require 'socket'

# Load Order is important here
require 'ntlm/exceptions'
require 'ntlm/field'
require 'ntlm/int16_le'
require 'ntlm/int32_le'
require 'ntlm/int64_le'
require 'ntlm/string'

require 'ntlm/field_set'
require 'ntlm/blob'
require 'ntlm/security_buffer'
# require 'ntlm/message'
# require 'ntlm/message/type0'
# require 'ntlm/message/type1'
# require 'ntlm/message/type2'
# require 'ntlm/message/type3'
#
# require 'ntlm/encode_util'
#
# require 'ntlm/client'
# require 'ntlm/channel_binding'
# require 'ntlm/target_info'
module NTLM
  module Util

    LM_MAGIC_TEXT = 'KGS!@#$%'
    TIME_OFFSET = 11644473600
    MAX64 = 0xffffffffffffffff
    module_function

    if RUBY_VERSION >= '1.9'

      def decode_utf16(str)
        str.encode(Encoding::UTF_8, Encoding::UTF_16LE)
      end

      def encode_utf16(str)
        str.to_s.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT)
      end

    else

      require 'iconv'

      def decode_utf16(str)
        Iconv.conv('UTF-8', 'UTF-16LE', str)
      end

      def encode_utf16(str)
        Iconv.conv('UTF-16LE', 'UTF-8', str)
      end

    end

    # Convert the value to a 64-Bit Little Endian Int
    # @param [String] val The string to convert
    def pack_int64le(val)
      [val & 0x00000000ffffffff, val >> 32].pack("V2")
    end

    def create_des_keys(string)
      keys = []
      string = string.dup
      until (key = string.slice!(0, 7)).empty?
        # key is 56 bits
        key = key.unpack('B*').first
        str = ''
        until (bits = key.slice!(0, 7)).empty?
          str << bits
          str << (bits.count('1').even? ? '1' : '0')  # parity
        end
        keys << [str].pack('B*')
      end
      keys
    end

    def encrypt(plain_text, key, key_length)
      key = key.ljust(key_length, "\0")
      keys = create_des_keys(key[0, key_length])

      result = ''
      cipher = OpenSSL::Cipher::DES.new
      keys.each do |k|
        cipher.encrypt
        cipher.key = k

        encrypted_text = cipher.update(plain_text)
        encrypted_text << cipher.final
        result << encrypted_text[0...8]
      end

      result
    end

    # [MS-NLMP] 3.3.1
    def lm_v1_hash(password)
      encrypt(LM_MAGIC_TEXT, password.upcase, 14)
    end

    # [MS-NLMP] 3.3.1
    def nt_v1_hash(password)
      OpenSSL::Digest::MD4.digest(encode_utf16(password))
    end

    # [MS-NLMP] 3.3.1
    def ntlm_v1_response(challenge, password, options = {})
      if options[:ntlm_v2_session]
        challenge = challenge.b if challenge.respond_to?(:b)
        client_challenge = options[:client_challenge] || OpenSSL::Random.random_bytes(8)
        client_challenge = client_challenge.b if client_challenge.respond_to?(:b)
        hash = OpenSSL::Digest::MD5.digest(challenge + client_challenge)[0, 8]
        nt_response = encrypt(hash, nt_v1_hash(password), 21)
        lm_response = client_challenge + ("\0" * 16)
      else
        nt_response = encrypt(challenge, nt_v1_hash(password), 21)
        lm_response = encrypt(challenge, lm_v1_hash(password), 21)
      end

      [nt_response, lm_response]
    end


    # [MS-NLMP] 3.3.2
    def nt_v2_hash(user, password, domain)
      user_domain = encode_utf16(user.upcase + domain)
      OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, nt_v1_hash(password), user_domain)
    end

    # [MS-NLMP] 3.3.2
    def ntlm_v2_response(user, password, domain, serverchal, ti, opt = {})
      puts "options in ntlm_v2_response " + opt.to_s

      key = nt_v2_hash(user, password, domain)
      serverchal = NTLM::pack_int64le(serverchal) if serverchal.is_a?(Integer)
      puts "ntlm_v2_response - ServerChal " + serverchal.unpack('H*').first.gsub(/..(?=.)/, '\0 ')

      if opt[:client_challenge] #client_challenge
        puts "hi"
        clientchallenge  = opt[:client_challenge]
      else
        puts "hello"
        clientchallenge = rand(MAX64).to_s
      end
      clientchallenge = NTLM::pack_int64le(clientchallenge) if clientchallenge.is_a?(Integer)

      if opt[:timestamp]
        ts = opt[:timestamp]
      else
        ts = Time.now.to_i
      end
      # epoch -> milsec from Jan 1, 1601
      ts = 10_000_000 * (ts + TIME_OFFSET)

      blob = Blob.new
      blob.timestamp = ts
      blob.challenge = clientchallenge
      blob.target_info = ti

      bb = blob.serialize

      # Concatenate the Type 2 challenge with our blob: i.e (serverchal + bb)
      # Apply HMAC-MD5 to this value using the NTLMv2 hash as the key to get the 16-byte value
      # This value is concatenated with the blob to obtain the NTLMv2 response

      OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, (serverchal.to_s + bb)) + bb
    end

    def lmv2_response(user, password, domain, serverchal, opt = {})
      puts opt.to_s
      key = nt_v2_hash(user, password, domain)

      serverchal = NTLM::pack_int64le(serverchal) if serverchal.is_a?(Integer)
      puts "lmv2_response - ServerChal " + serverchal.unpack('H*').first.gsub(/..(?=.)/, '\0 ')

      if opt[:client_challenge]
        cc  = opt[:client_challenge]
        puts "lmv2_response - clientChal " + cc.unpack('H*').first.gsub(/..(?=.)/, '\0 ')
      else
        cc = rand(MAX64).to_s
      end
      cc = NTLM::pack_int64le(cc) if cc.is_a?(Integer)

      OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, serverchal + cc) + cc
    end

    def final_ntlm_v2_response(user, domain, password, challenge, targetinfo, options = {})
      puts "final_ntlm_v2_response options :"+ options.to_s
      ntv2_response = ntlm_v2_response(user, password, domain, challenge, targetinfo, options)
      lmv2_response = lmv2_response(user, password, domain, challenge, options)
      puts "final_ntlm_v2_response ntv2_response :"+ ntv2_response.unpack('H*').first.gsub(/..(?=.)/, '\0 ')
      puts "final_ntlm_v2_response lmv2_response :"+ lmv2_response.unpack('H*').first.gsub(/..(?=.)/, '\0 ')
      [ntv2_response, lmv2_response]
    end

  end # Util
end # NTLM
