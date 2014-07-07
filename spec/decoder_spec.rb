require 'spec_helper'

describe 'Decoder' do
  before do
    @payload = { 'hello' => 'world', 'iat' => 946681200 }
  end

  it 'decodes a valid JWT using HS' do
    secret          = 'mysecret'
    jwt             = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.9OzXVFu0LK4miYiSkWrP5vhzHVtz5DHC8dWalkTah3c'
    payload, header = JWT.decode(jwt, secret)

    expect(payload).to eq(@payload)
  end

  it 'decodes a valid JWT using RS' do
    public_key = OpenSSL::PKey::RSA.new(<<-KEY)
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAUTQbhg/Hcgq26wY9yOWu9L6OX4fqekqo
R+YhQUXaJGXhW0tNapTdIwTAycby0cUCXoA/7IYi4SXSKMT0owQxeQIDAQAB
-----END PUBLIC KEY-----
KEY

    jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.A0Qiqmo02gEviZtQW8ESC94oKLXcgCSGnktyxDQZNE0AfSoMJZ9JMEWNjEXyp6k7VEm9nn9ZbEu2GdmAIJz-xw'
    payload, header = JWT.decode(jwt, public_key, algorithm: 'RS256')

    expect(payload).to eq(@payload)
  end

  it 'raises an error if you use a string as a key in RS decoding' do
    secret = 'mysecret'
    jwt    = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.E0f3M2R4p1_pEmDFp3PZNfXwLp6m3z7MNX468o8gQCYeslnOMdCGvzl1pCJhDs5M7KnaSlvPm_Be3WjYrk8ZDQ'

    expect { JWT.decode(jwt, secret, algorithm: 'RS256') }
      .to raise_error JWT::Verificator::ClassMethods::InvalidKeyFormatError
  end

  it 'raises an error if you dont use a string as a key in HS decoding' do
    key = OpenSSL::PKey::RSA.new(<<-KEY)
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAUTQbhg/Hcgq26wY9yOWu9L6OX4fqekqo
R+YhQUXaJGXhW0tNapTdIwTAycby0cUCXoA/7IYi4SXSKMT0owQxeQIDAQAB
-----END PUBLIC KEY-----
KEY

    jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.E0f3M2R4p1_pEmDFp3PZNfXwLp6m3z7MNX468o8gQCYeslnOMdCGvzl1pCJhDs5M7KnaSlvPm_Be3WjYrk8ZDQ'

    expect { JWT.decode(jwt, key) }
      .to raise_error JWT::Verificator::ClassMethods::InvalidKeyFormatError
  end

  it 'raises an error if the token doesnt have the correct number of segments' do
    secret = 'mysecret'
    jwt    = 'header.payload.signature.hello?'

    expect { JWT.decode(jwt, key) }
      .to raise_error StandardError
  end

  it 'raises an error if the token cant be verified with the current secret key' do
    secret = 'myothersecret'
    jwt    = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'

    expect { JWT.decode(jwt, secret) }
      .to raise_error StandardError
  end

  it 'raises an error if there is no header' do
    secret = 'myothersecret'
    jwt    = '.eyJoZWxsbyI6IndvcmxkIn0.Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'

    expect { JWT.decode(jwt, secret) }
    .to raise_error StandardError
  end

  it 'raises an error if there is no payload' do
    secret = 'myothersecret'
    jwt    = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'

    expect { JWT.decode(jwt, secret) }
    .to raise_error StandardError
  end

  it 'validates a JWT with the correct audience' do
    expected_payload = { 'hello' => 'world', 'iat' => 946681200, 'aud' => 'rubyist' }
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImF1ZCI6InJ1Ynlpc3QifQ.u6DB-dpK5zxZUmgprzXtg5yY4djsLLtIv4EAgE_nWSM'

    payload, header = JWT.decode(jwt, secret, claims: { aud: 'rubyist' })

    expect(payload).to eq(expected_payload)
  end

  it 'raises an error if the audience doesnt match' do
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImF1ZCI6InJ1Ynlpc3QifQ.u6DB-dpK5zxZUmgprzXtg5yY4djsLLtIv4EAgE_nWSM'

    expect { JWT.decode(jwt, secret, claims: { aud: 'phpers' })}
      .to raise_error StandardError
  end

  it 'validates a JWT with the correct issuer' do
    expected_payload = { 'hello' => 'world', 'iat' => 946681200, 'iss' => 'toni' }
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImlzcyI6InRvbmkifQ.I4EoPQzt97rehCBnU8VTcDH5R2KX6b8Ta1t5bANGorc'

    payload, header = JWT.decode(jwt, secret, claims: { iss: 'toni' })

    expect(payload).to eq(expected_payload)
  end

  it 'raises an error if the issuer doesnt match' do
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImlzcyI6InRvbmkifQ.I4EoPQzt97rehCBnU8VTcDH5R2KX6b8Ta1t5bANGorc'

    expect { JWT.decode(jwt, secret, claims: { iss: 'john' })}
    .to raise_error StandardError
  end

  it 'validates a JWT with expiry if it didnt expire yet' do
    # The expiry is set to 24 hours
    expected_payload = { 'hello' => 'world', 'iat' => 946681200, 'exp' => 946767600}
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImV4cCI6OTQ2NzY3NjAwfQ.AZ9a_9L8oY95OT7jc019ZxjWc9fcT5chYsZy6QUgzj0'

    # Travel 12 hours in the future
    Timecop.travel(Time.at(946724400))

    payload, header = JWT.decode(jwt, secret)

    expect(payload).to eq(expected_payload)
  end

  it 'raises an error if the token expired' do
    # The expiry is set to 24 hours
    secret           = 'mysecret'
    jwt              = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImV4cCI6OTQ2NzY3NjAwfQ.AZ9a_9L8oY95OT7jc019ZxjWc9fcT5chYsZy6QUgzj0'

    # Travel 24 hours, 1 second in the future
    Timecop.travel(Time.at(946767601))

    expect { JWT.decode(jwt, secret) }
      .to raise_error StandardError
  end
end

