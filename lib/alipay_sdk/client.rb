module AlipaySdk
  class Client
    attr_accessor :gateway, :app_id, :private_key, :alipay_public_key, :alipay_aes_key, :sign_type
    attr_accessor :alipay_public_cert_path

    def initialize(options = {})
      @app_id = options[:app_id]
      @gateway = options[:gateway] || "https://openapi.alipay.com/gateway.do"
      @private_key = set_cert_format(options[:private_key], 'RSA PRIVATE KEY')
      @alipay_public_key = set_cert_format(options[:alipay_public_key], 'PUBLIC KEY')
      @alipay_aes_key = options[:alipay_aes_key]
      @sign_type = options[:sign_type] || 'RSA2'
    end

    def execute(method, content = {}, params = {})
      if !content.empty?
        request_config[:biz_content] = content.to_json
      end
      query = request_config.merge(params)
      sign_str = Signature.generate(resort_query(query), private_key)
      resp = request(query.merge(sign: sign_str))
      return MultiJson.load(resp.body.encode!('utf-8', 'gbk'))
    end

   # 解密支付宝加密信息(手机号码等)
    def decrypt(str)
      encrypt_content = Base64.strict_decode64(str)
      aes = OpenSSL::Cipher::AES.new("128-CBC")
      aes.decrypt
      aes.key = Base64.strict_decode64(@alipay_aes_key)
      content = aes.update(encrypt_content) + aes.final
      return MultiJson.load(content.force_encoding('utf-8'))
    end

    def verify?(sign_data, str)
      decrypt_sign = Base64.strict_decode64(sign_data)
      pkey = OpenSSL::PKey::RSA.new(alipay_public_key)
      digest = OpenSSL::Digest::SHA256.new
      pkey.verify(digest, decrypt_sign, str.to_json)
    end

    private

    def request(params = {})
      query = URI.encode_www_form(params)
      return Faraday.post(gateway, query)
    end

    def resort_query(query = {})
      _query = query
      _query.delete_if{ |key, value| value.nil? || value == '' }
      sign_str = _query.sort.to_h.map do |key,value|
        "#{key}=#{value}"
      end.join("&")
    end

    def set_cert_format(key, type)
      return key if key.match(type)
      pem_str = key.gsub("\r\n", '').gsub(/-----[^-]+-----/,'').to_s
      pem = 0.upto(pem_str.length/64).to_a.map{|len| pem_str[len * 64, 64]}.join("\n")
      return "-----BEGIN #{type}-----\n#{pem}\n-----END #{type}-----"
    end

    def request_config
      {
        app_id: app_id,
        sign_type: sign_type,
        charset: 'utf-8',
        version: '1.0',
        format: 'json',
        timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S")
      }
    end
  end
end
