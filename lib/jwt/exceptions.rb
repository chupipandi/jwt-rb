module JWT
  class VerificationError < StandardError
  end

  class InvalidKeyFormatError < StandardError
  end

  class DecoderError < StandardError
  end
end
