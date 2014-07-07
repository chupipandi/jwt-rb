module JWT
  class Decoder
    include JWT::Verificator
    include JWT::Signature

    class << self
      def decode(jwt, key, options)
        @algorithm = options[:algorithm] || 'HS256'
        @jwt       = jwt
        
        validate_jwt!

        header, payload, input, signature = decode_token
        
        verify_claims!(payload, options[:claims])
        verify_signature!(key, signature, input)

        [payload, header]
      end

      private

      def validate_jwt!
        fail StandardError.new('Invalid JWT') if parse_token.length != 3
      end

      def parse_token
        @jwt.split('.')
      end

      def decode_token
        header, payload, signature = parse_token

        input     = [header, payload].join('.') 
        header    = decode_header(header)
        payload   = decode_payload(payload)
        signature = decode_signature(signature)

        [header, payload, input, signature]
      end

      def decode_header(header)
        fail StandardError if header.empty?
        header = base64_decode(header)
        JSON.parse(header)
      end

      def decode_payload(payload)
        fail StandardError if payload.empty?
        payload = base64_decode(payload)
        JSON.parse(payload)
      end

      def decode_signature(signature)
        base64_decode(signature)
      end

      def base64_decode(string)
        string += '=' * (4 - string.length.modulo(4))
        Base64.decode64(string.tr('-_','+/'))
      end

      def verify_signature!(key, signature, input)
        supported_algorithm!(@algorithm)

        parsed_algorithm = parse_algorithm(@algorithm)
        digest           = generate_digest(parsed_algorithm)

        if @algorithm =~ /^HS/
          hs_key_format!(key)
          signed_input = sign_hmac(digest, key, input)
          fail StandardError unless secure_compare(signature, signed_input)
        else
          rs_key_format!(key)
          verify_rsa(key, digest, signature, input)
        end
      end

      # From devise & inspired from ruby-jwt of http://github.com/progrium
      # constant-time comparison algorithm to prevent timing attacks
      def secure_compare(a, b)
        return false if a.nil? || b.nil? || a.empty? || b.empty? || a.bytesize != b.bytesize
        l = a.unpack "C#{a.bytesize}"

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
      end
    end
  end
end

