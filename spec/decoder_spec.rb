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
    key = OpenSSL::PKey::RSA.new(<<-PIVKEY)
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJAa3OaqnpApn6lqTVCefBLjcXxiN22Ks3HZcyy4xnxhlJK1MxqNMJs
FLCvIIwsMBFrHpWs+iZ8SCA2GzvoPn5wlwIDAQABAkBKAt20sPJY/AD1VNcOEKKp
637bzAMO5qCCkQVigdsnriCab5AL+2M4f4XD6jI5OJkG6KZzse96PjmaTyWwZcvB
AiEApycN0oyYeEISG14YUntH4zmiOSJb+rhZrRH+z45B+SECIQCkkNxM+IhTCp4W
hZLDTYum329QOfHPyEjEi7if8QgatwIgY8/AQz/NM9JQOaNgZrBS5u5dXjyULAy1
D9G1FH9gCcECIQCKaTBxKKP4PDjktmnPDBzGOKz17BZ+7XSOovmgxGhNlwIhAIaQ
/z9AMGKMCwy1/oGt6viqaY/Kdnh6CrkvEofRAdzB
-----END RSA PRIVATE KEY-----
PIVKEY

    jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.E0f3M2R4p1_pEmDFp3PZNfXwLp6m3z7MNX468o8gQCYeslnOMdCGvzl1pCJhDs5M7KnaSlvPm_Be3WjYrk8ZDQ'
    payload, header = JWT.decode(jwt, key, algorithm: 'RS256')

    expect(payload).to eq(@payload)
  end

  it 'raises an error if you use a string as a key in RS decoding' do
    secret = 'mysecret'
    jwt    = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.E0f3M2R4p1_pEmDFp3PZNfXwLp6m3z7MNX468o8gQCYeslnOMdCGvzl1pCJhDs5M7KnaSlvPm_Be3WjYrk8ZDQ'

    expect { JWT.decode(jwt, secret, algorithm: 'RS256') }
      .to raise_error JWT::Verificator::ClassMethods::InvalidKeyFormatError
  end

  it 'raises an error if you dont use a string as a key in HS decoding' do
    key = OpenSSL::PKey::RSA.new(<<-PIVKEY)
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJAa3OaqnpApn6lqTVCefBLjcXxiN22Ks3HZcyy4xnxhlJK1MxqNMJs
FLCvIIwsMBFrHpWs+iZ8SCA2GzvoPn5wlwIDAQABAkBKAt20sPJY/AD1VNcOEKKp
637bzAMO5qCCkQVigdsnriCab5AL+2M4f4XD6jI5OJkG6KZzse96PjmaTyWwZcvB
AiEApycN0oyYeEISG14YUntH4zmiOSJb+rhZrRH+z45B+SECIQCkkNxM+IhTCp4W
hZLDTYum329QOfHPyEjEi7if8QgatwIgY8/AQz/NM9JQOaNgZrBS5u5dXjyULAy1
D9G1FH9gCcECIQCKaTBxKKP4PDjktmnPDBzGOKz17BZ+7XSOovmgxGhNlwIhAIaQ
/z9AMGKMCwy1/oGt6viqaY/Kdnh6CrkvEofRAdzB
-----END RSA PRIVATE KEY-----
PIVKEY

    jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.E0f3M2R4p1_pEmDFp3PZNfXwLp6m3z7MNX468o8gQCYeslnOMdCGvzl1pCJhDs5M7KnaSlvPm_Be3WjYrk8ZDQ'

    expect { JWT.decode(jwt, key) }
      .to raise_error JWT::Verificator::ClassMethods::InvalidKeyFormatError
  end
end
