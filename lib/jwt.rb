require 'jwt/payload'
require 'jwt/verificator'
require 'jwt/signature'
require 'jwt/encoder'
require 'jwt/decoder'
require 'json'
require 'base64'
require 'openssl'

module JWT
  module ModuleFunctions
    def encode(payload, key, options = {})
      Encoder.encode(payload, key, options)
    end

    def decode(jwt, key, options = {})
      Decoder.decode(jwt, key, options)
    end
  end

  extend ModuleFunctions
end

