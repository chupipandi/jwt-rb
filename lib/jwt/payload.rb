require 'hashie'

module JWT
  class Payload < Hash
    include Hashie::Extensions::MergeInitializer
    include Hashie::Extensions::IndifferentAccess
  end
end
