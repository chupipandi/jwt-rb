module JWT
  module Signature
    def self.included(base)
      base.extend ClassMethods
    end

    module ClassMethods

      private

      def parse_algorithm(algorithm)
        algorithm.sub(/^../, 'sha')
      end

      def generate_digest(parsed_algorithm)
        OpenSSL::Digest.new(parsed_algorithm)
      end

      def sign_hmac(digest, key, input)
        OpenSSL::HMAC.digest(digest, key, input)
      end

      def sign_rsa(key, digest, input)
        key.sign(digest, input) rescue StandardError.new('Your key needs to be able to .sign()')
      end

      def verify_rsa(key, digest, signature, input)
        fail StandardError unless key.verify(digest, signature, input)
      end
    end
  end
end

