module AlipaySdk
  class Signature
    def self.generate(sign_str, private_key)
      pkey = OpenSSL::PKey::RSA.new(private_key)
      digest = OpenSSL::Digest::SHA256.new
      Base64.strict_encode64(pkey.sign(digest, sign_str))
    end
  end
end
