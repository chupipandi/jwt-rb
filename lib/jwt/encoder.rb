require 'json'
require 'base64'
require 'openssl'

module JWT
  class Encoder
    class << self
      SUPPORTED_ALGS = %w(HS256 HS384 HS512 RS256 RS384 RS512)

      def encode(payload, key, options)
        @algorithm = options[:algorithm] || 'HS256'

        header    = encode_header
        payload   = encode_payload(payload)
        signature = encode_signature(header, payload, key)

        [header, payload, signature].join('.')
      end

      private

      def encode_header
        base64(header)
      end

      def header
        { typ: 'JWT', alg: @algorithm }.to_json
      end

      def encode_payload(payload)
        base64(payload.to_json)
      end

      def base64(string)
        Base64.encode64(string).tr('+/', '-_').gsub(/[\n=]/, '')
      end

      def encode_signature(header, payload, key)
        input     = [header, payload].join('.')
        signature = sign(input, key)

        base64(signature)
      end

      def sign(input, key)
        if !SUPPORTED_ALGS.include? @algorithm
          fail NotImplementedError.new("#{@algorithm} is not supported")
        end

        parsed_algorithm = @algorithm.sub(/^../, 'sha')
        digest           = OpenSSL::Digest.new(parsed_algorithm)

        if @algorithm =~ /^HS/
          OpenSSL::HMAC.digest(digest, key, input)
        else
          key.sign(digest, input) rescue StandardError.new('Your key needs to be able to .sign()')
        end
      end
    end
  end
end
