require 'spec_helper'

describe 'Encoder' do
  before do
    Timecop.freeze(Time.at(946681200))
    @payload = { hello: 'world' }
  end

  it 'encodes a JWT using HS' do
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.9OzXVFu0LK4miYiSkWrP5vhzHVtz5DHC8dWalkTah3c'
    jwt          = JWT.encode(@payload, secret)

    expect(jwt).to eq(expected_jwt)
  end

  it 'encodes a JWT using RS' do
    key = OpenSSL::PKey::RSA.new(<<-KEY)
-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJAUTQbhg/Hcgq26wY9yOWu9L6OX4fqekqoR+YhQUXaJGXhW0tNapTd
IwTAycby0cUCXoA/7IYi4SXSKMT0owQxeQIDAQABAkBI9IfF6mdGDlpIzVK1K6YE
PS+spHAFbw3BiwBVpGxYRiumQrZyjKfpPpXw1dM9Qrm0Q3hXPLEzB3Ea/aw3rAAB
AiEAoGHNoRMeBnMC7mwbi8rf8RFriWpTp91IoFzD+oPV/fECIQCBnb3Tn4Uxccmd
2L+yoYMottUTVONq8l2YDBQlTG6ECQIgcLBHq0WjcySciqmrMS3664cx5/uti+UP
gp2rlfnMAgECIAfVedilho5Te0UQCZ4JRv0Z98zgT5JyLZf3+uu6L9/JAiBubUAY
c1CuIOv3cWDJPNMWI57s1U2WF+zbtIkc1zr5+Q==
-----END RSA PRIVATE KEY-----
KEY
    jwt          = JWT.encode(@payload, key, algorithm: 'RS256')
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.A0Qiqmo02gEviZtQW8ESC94oKLXcgCSGnktyxDQZNE0AfSoMJZ9JMEWNjEXyp6k7VEm9nn9ZbEu2GdmAIJz-xw'
    expect(jwt).to eq(expected_jwt)
  end

  it 'raises NotImplementedError using a fake signature' do
    secret = 'mysecret'
    expect { JWT.encode(@payload, secret, algorithm: 'HS9888889') }
      .to raise_error NotImplementedError
  end

  it 'raises an error if you dont use a private key on RS algorithms' do
    secret = 'mysecret'
    expect { JWT.encode(@payload, secret, algorithm: 'RS256') }
      .to raise_error StandardError
  end

  it 'can use a payload with string as keys' do
    payload      = { 'hello' => 'world' }
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.9OzXVFu0LK4miYiSkWrP5vhzHVtz5DHC8dWalkTah3c'
    jwt          = JWT.encode(payload, secret)

    expect(jwt).to eq(expected_jwt)
  end

  it 'can use old ruby hash style' do
    payload      = { :hello => 'world' }
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDB9.9OzXVFu0LK4miYiSkWrP5vhzHVtz5DHC8dWalkTah3c'
    jwt          = JWT.encode(payload, secret)

    expect(jwt).to eq(expected_jwt)
  end

  it 'allows you to set an expiry time' do
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImV4cCI6OTQ2Njg3MjAwfQ.zbalHdCubQpn_U32jW1dv9L2p3vWSgf-UsKwnEiFxWo'
    jwt          = JWT.encode(@payload, secret, claims: { exp: 6000 })

    expect(jwt).to eq(expected_jwt)
  end

  it 'allows you to set an audience' do
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImF1ZCI6InJ1Ynlpc3QifQ.u6DB-dpK5zxZUmgprzXtg5yY4djsLLtIv4EAgE_nWSM'
    jwt          = JWT.encode(@payload, secret, claims: { aud: 'rubyist' })

    expect(jwt).to eq(expected_jwt)
  end

  it 'allows you to set an issuer' do
    secret       = 'mysecret'
    expected_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0Ijo5NDY2ODEyMDAsImlzcyI6InRvbmkifQ.I4EoPQzt97rehCBnU8VTcDH5R2KX6b8Ta1t5bANGorc'
    jwt          = JWT.encode(@payload, secret, claims: { iss: 'toni' })

    expect(jwt).to eq(expected_jwt)
  end
end

