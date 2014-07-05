module JWT
  class Encoder
    include JWT::Verificator
    include JWT::Signature

    class << self
      def encode(payload, key, options)
        @algorithm = options[:algorithm] || 'HS256'

        header    = encode_header
        payload   = encode_payload(payload)
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

      def encode_payload(payload)
        base64_encode(payload.to_json)
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
          sign_hmac(digest, key, input)
        else
          sign_rsa(key, digest, input)
        end
      end
    end
  end
end

