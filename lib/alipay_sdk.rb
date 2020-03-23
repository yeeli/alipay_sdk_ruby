require 'active_support/concern'
require 'faraday'
require 'openssl'
require 'base64'
require 'multi_json'
require "alipay_sdk/version"
require "alipay_sdk/client"
require "alipay_sdk/signature"

module AlipaySdk
  class Error < StandardError; end
end
