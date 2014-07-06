require 'spec_helper'

describe 'Decoder' do
  before do
    @payload = { 'hello' => 'world' }
  end

  it 'decodes a valid JWT using HS' do
    secret          = 'mysecret'
    jwt             = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'
    payload, header = JWT.decode(jwt, secret)

    expect(payload).to eq(@payload)
  end

  it 'decodes a valid JWT using RS' do
    public_key = OpenSSL::PKey::RSA.new(<<-KEY)
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbHUyVoS3o2iNuAZv/Rw5CjBu3/FTTce+
kQraVpHf0iDVKsjGkZ8xDz/6SqKKze9F5RifzB7g4XTjO9EUtd4uzwIDAQAB
-----END PUBLIC KEY-----
KEY

    jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.Yj_YlEqKVNWciKA10zNr_ygyiCJB_mByNiX-4lX9Q9Capdzze-CrruC7ddY8rMnRfyIcDXhpcD4fENvxiamgZQ'
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
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbHUyVoS3o2iNuAZv/Rw5CjBu3/FTTce+
kQraVpHf0iDVKsjGkZ8xDz/6SqKKze9F5RifzB7g4XTjO9EUtd4uzwIDAQAB
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

    expect { JWT.decode(jwt, key) }
      .to raise_error StandardError
  end

  it 'raises an error if there is no header' do
    secret = 'myothersecret'
    jwt    = '.eyJoZWxsbyI6IndvcmxkIn0.Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'

    expect { JWT.decode(jwt, key) }
    .to raise_error StandardError
  end

  it 'raises an error if there is no payload' do
    secret = 'myothersecret'
    jwt    = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..Gc_-AK7EN0nCQj6egXy525yk_cssK2A2lgX-w2NM90M'

    expect { JWT.decode(jwt, key) }
    .to raise_error StandardError
  end
end

