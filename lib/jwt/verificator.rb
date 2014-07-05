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
    end
  end
end

