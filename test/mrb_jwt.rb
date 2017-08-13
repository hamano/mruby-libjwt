##
## JWT Test
##

assert("JWT#new") do
  jwt = JWT.new
  assert_equal(jwt.to_s, '{"alg":"none"}.{}')
end

assert("JWT#add_grants(json)") do
  jwt = JWT.new
  jwt.add_grants('{"foo":"bar"}')
  assert_equal(jwt.to_s, '{"alg":"none"}.{"foo":"bar"}')
end

assert("JWT#add_grants(hash)") do
  jwt = JWT.new
  jwt.add_grants({"foo" => "bar"})
  assert_equal(jwt.to_s, '{"alg":"none"}.{"foo":"bar"}')
end

assert("JWT#hs256 encode") do
  jwt = JWT.new
  jwt.add_grants('{"sub":"1234567890","name": "John Doe","admin": true}')
  jwt.set_alg(JWT::ALG_HS256, "secret")
  assert_equal(jwt.encode, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.a2ce1BjLKoQZ2sWjrieL7mb-eHsOne0sA1vUcW88Tns')
end

assert("JWT#rs256 encode") do
  KEY = <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3UUypo3F8ZvQjdmrTm6xwIbm2xZ2fY9B7WYOtlq3jmF8HKUR
i0Q7W9W4p5W6Q4c7v+h+hnSaujqXErqAC+XZh/VmSyPDaAPB8LzNBCW1eC51t5Yr
tmRCgHMNsKi8Q8ZG8IcnBUnHJWdw2sUDq55lI/L0Hh0L60A2Qpuwah7EbaNJQqEk
CwEMGYgJNt4osk3araWeQ/TCPmdWcr27d6+d7CFLB3qw+cmHCVio+4j9FWVNNAFo
CpKs8yPz2BFbLWXAWqAJZcyvhC1U68dahigThZ9p+kJqbjt6nbFgOhQhc57a5sSS
ntTc/yK5fnKeN883UPvn+M41jujfhIYkLKKrkwIDAQABAoIBAQCi1zUye+3sJLa0
XjgDTdXFEcK+A+cJ+q8TLmOvck3aHAZB8n1Z18oziLMPqlJdNh4T2t+axh/E5C+g
Wd64YtzXgRNaQySg3PsS12+uGK5XlyGNDZh374s9iu7NTzDWVAqLI3vlGWnVLi5Q
4mMUH0rhzQA5VTkbVbNZC8kmICSBZiaPnlrIbU2fiFqtHPXpIm8FfDE7Ijw9X06h
+/NkxIrReA2i3kTiyRQMYByPk+BIo9TQAnes9g7lvxkoiv1Z3gaosHyKiBWa3JKs
4GWUXwTli1hUEBVUr8PnW+Bkj47T/kF96J9V6s85dMOhPwMKCEKhDj4yoFwGKZjX
qgFwMxjpAoGBAPaneC34FO484LvEcz8kE17Dasrm3sUu2w1EQZmI4o+7+aOkew/L
dVUX0eWfUWYLHSyGoNtYZDNSlqF3Wi3yNvpthEqVyA5GZ2jyqYSOnZ45LT3w20Qn
XR2YMY4CVZIdoICOip7w7/6L6KzCEy6TpXG9b8GhyuelIL5WLVfagr4FAoGBAOWn
gaGLEE4NXliJqZC6rerCCb7635ZFrIZ9hSSm4tc95xryxWpCz9SPpQXuorD6AeiT
I6ZR23DYA14Ws/M6eYqLTmgweSVOAN9eun4n90hKdwNuEtan6RDoOQLh7wCFh5li
Zprh5McoeiraKB3mrGoJWsJqiDEofBRfOMfve163AoGBAMbDNal1nQhOrpshN+3N
2H4o48oWObaUh5ktQ9/B2zEQvZ8NUM3tmuOzikWMGUAt/JiA9OdNV5G0IAaF83nL
ElrEHjMseEZonbSIt+pGMuXqFXcwvMEzJ2pN1sElSGey0EBInZRvfDaX8CwnSOXj
vRLnIUPcaXI6MySutWNyhqExAoGAQExm2gDifsf1a1qXtCLgQMM1EViSMzOsuzb3
iSyEhHkbdIsWRMsR/1R8gq2utVg6IpDXwWBXzT9dqgE3PtlXYDfiqv8vXAd77Q5L
rrin3oCi074E3j7C3W33UFxLm1zHe2V2jtTCRhSKJ+dOphiIm2OlGpvTJ9hK7TU/
45Kkev8CgYEApBxdl4Ikl6YAtM4UMxxcGRbb9EwTB3sDB+ZSLVXKP85cvsJtu1r0
Km6MuLc5HeFobxOcK2O64oqd4vtL2p6IRRFYE8K7K59N2l14Wkeq4y2IV/A1DmtC
ds3xkh80iJS4FyXm/owfXU5UgnzC4S5cW9v4lmwLxTx6DbDQ6VN7WFc=
-----END RSA PRIVATE KEY-----
EOF
  jwt = JWT.new
  jwt.add_grants('{"sub":"1234567890","name": "John Doe","admin": true}')
  jwt.set_alg(JWT::ALG_RS256, KEY)
  assert_equal(jwt.encode, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.V-6mCQ4x5YK0mG9qG90-C5iA26Pbu1_E9Ql2Ceeskg_Gm4NI_p-mX1vplJq5Je4z-RdonQeZkCJ2hBaTdsqtivnuxCNNsz14pmdF3WObmUnSvsYhvyZjw2IQ4a3No8ILnmb6Qn4dYIRQV9E1cIQdIfeBQYoUvZ2hcKOGuC9fVT_ZS4unXB0YDqsDYL4dwLNsFiuyTaQwLCS3Jqy10-89R_4h-m3BmCIe_36PaifG1axJeIHK1z81ATpOIDSuWFlI9eLjx-k6s7FLeiX6kc2KPgy7ddvrkTpVzZFaY5ptGCF7cGICcH0nGGHn_XCHpo321KyBpNCBaHTuRcvgxgk3Sg')
end

