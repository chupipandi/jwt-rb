# Jwt-rb
[![Code Climate](https://codeclimate.com/github/chupipandi/jwt-rb.png)](https://codeclimate.com/github/chupipandi/jwt-rb) [![Build Status](https://travis-ci.org/chupipandi/jwt-rb.svg?branch=master)](https://travis-ci.org/chupipandi/jwt-rb) [![Gem Version](https://badge.fury.io/rb/jwt-rb.svg)](http://badge.fury.io/rb/jwt-rb)

## Installation

Add this line to your application's Gemfile

    gem 'jwt-rb'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jwt-rb
    
Then you just need to require it where needed:

```ruby
require 'jwt'
```

## Usage

`jwt-rb` has two methods, one for encoding, one for decoding:

###JWT.encode(payload, key, options)

`payload` is a hash which contains the data we want to embed into the token.

`key` could be a secret string to use in `HMAC` algorithms or a private key for `RSA` algorithms.

`options`:

* `algorithm`: Algorithm to use, default is `HS256`.
* `claims` (They are optional):
    * `exp`: Time until the token expires, in seconds.
    * `aud`: Intended audience of the token.
    * `iss`: Identifies the issuer of the token.
    
####Examples:

Basic token:
```ruby
token = JWT.encode({ hello: 'world' }, 'thisismysecret')
```

Token with expiration (24 hours):
```ruby
token = JWT.encode({ hello: 'world' }, 'thisismysecret', claims: { exp: 86400 })
```

Token with RSA key:
```ruby
private_key = OpenSSL::PKey::RSA.generate(512)
token = JWT.encode({ hello: 'world' }, key, algorithm: 'RS256')
```

###JWT.decode(token, key, options)

`token` is the JWT string we encoded before.

`key` could be a secret string to use in `HMAC` algorithms or a private key for `RSA` algorithms.

`options`:
 
* `algorithm` : Algorithm to be used to verify the token.
* `claims`:
    * `aud`: Audience of the token to verify if it matches with the token.
    * `iss`: Issuer of the token to verify if it matches with the token.

####Examples:

Basic decoding:
```ruby
jwt = 'string containing real jwt token'
payload, header = JWT.decode(jwt, 'thisismysecret')
```

Decoding with RSA:
```ruby
# private key used to sign the token
private_key = OpenSSL::PKey::RSA.generate(512)
jwt = 'string containing real jwt token'
payload, header = JWT.decode(jwt, private_key.public_key, algorithm: 'RS256')
```

Decoding a token with claims:
```ruby
jwt = 'string containing real jwt token'
payload, header = JWT.decode(jwt, 'thisismysecret', claims: { aud: 'foo' })
```
    
###Supported Algorithms

Algorithm parameter | Algorithm used
----------|-------
HS256 | HMAC using SHA-256 algorithm
HS384 | HMAC using SHA-384 algorithm
HS512 | HMAC using SHA-512 algorithm
RS256 | RSA using SHA-256 algorithm
RS384 | RSA using SHA-384 algorithm
RS512 | RSA using SHA-512 algorithm
        
## Contributing

1. Fork it ( https://github.com/chupipandi/jwt-rb/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

MIT
