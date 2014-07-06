module JWT
  module Verificator
    def self.included(base)
      base.extend ClassMethods
    end

    module ClassMethods
      SUPPORTED_ALGS = %w(HS256 HS384 HS512 RS256 RS384 RS512)
      private

      def supported_algorithm!(algorithm)
        if !SUPPORTED_ALGS.include? algorithm
          fail NotImplementedError.new("#{algorithm} is not supported")
        end
      end

      def hs_key_format!(key)
        fail InvalidKeyFormatError unless key.is_a? String
      end

      def rs_key_format!(key)
        fail InvalidKeyFormatError unless key.is_a? OpenSSL::PKey::RSA
      end

      def valid_integer_claim(claim)
        claim.is_a? Integer
      end

      def valid_string_claim(claim)
        claim.is_a? String
      end

      def verify_claims!(payload, options)
        validate_expiration(payload[:exp]) if payload[:exp]
        validate_audience(payload[:aud], options[:aud]) if payload[:aud]
        validate_issuer(payload[:iss], options[:iss]) if payload[:iss]
      end

      def validate_expiration(exp)
        raise StandardError if Time.now.to_i >= exp
      end

      def validate_audience(aud, given_aud)
        raise StandardError if given_aud && given_aud != aud
      end

      def validate_issuer(iss, given_iss)
        raise StandardError if given_iss && given_iss != iss
      end

      class InvalidKeyFormatError < StandardError
      end
    end
  end
end

