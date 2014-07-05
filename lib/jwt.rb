require 'jwt/encoder'

module JWT
  module ModuleFunctions
    def encode(payload, key, options = {})
      Encoder.encode(payload, key, options)
    end

    def decode(jwt, key, options = {})
      Decoder.decode!(jwt, key, options = {})
    end
  end

  extend ModuleFunctions
end
