module JWT
  class Encoder
    include JWT::Verificator
    include JWT::Signature

    class << self
      def encode(payload, key, options)
        @algorithm = options[:algorithm] || 'HS256'
        @payload   = Payload.new(payload)

        header    = encode_header
        payload   = decorate_and_encode_payload(options[:claims] || {})
        signature = encode_signature(header, payload, key)

        [header, payload, signature].join('.')
      end

      private

      def encode_header
        base64_encode(header)
      end

      def header
        { typ: 'JWT', alg: @algorithm }.to_json
      end

      def encode_payload
        base64_encode(@payload.to_json)
      end

      def decorate_and_encode_payload(claims)
        @payload[:iat] = Time.now.to_i
        @payload[:exp] = @payload[:iat] + claims[:exp] if valid_integer_claim(claims[:exp])
        @payload[:aud] = claims[:aud] if valid_string_claim(claims[:aud])
        @payload[:iss] = claims[:iss] if valid_string_claim(claims[:iss])

        encode_payload
      end

      def base64_encode(string)
        Base64.encode64(string).tr('+/', '-_').gsub(/[\n=]/, '')
      end

      def encode_signature(header, payload, key)
        input     = [header, payload].join('.')
        signature = sign(input, key)

        base64_encode(signature)
      end

      def sign(input, key)
        supported_algorithm!(@algorithm)

        parsed_algorithm = parse_algorithm(@algorithm)
        digest           = generate_digest(parsed_algorithm)

        if @algorithm =~ /^HS/
          hs_key_format!(key)
          sign_hmac(digest, key, input)
        else
          rs_key_format!(key)
          sign_rsa(key, digest, input)
        end
      end
    end
  end
end

