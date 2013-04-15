#
# Author:: Christopher Brown (<cb@opscode.com>)
# Author:: Christopher Walters (<cw@opscode.com>)
# Copyright:: Copyright (c) 2009, 2010 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'net/http'
require 'forwardable'
require 'mixlib/authentication'
require 'mixlib/authentication/http_authentication_request'
require 'mixlib/authentication/signedheaderauth'

module Mixlib
  module Authentication

    SignatureResponse = Struct.new(:name)

    class SignatureVerification
      extend Forwardable

      def_delegator :@auth_request, :http_method

      def_delegator :@auth_request, :path

      def_delegator :@auth_request, :signing_description

      def_delegator :@auth_request, :user_id

      def_delegator :@auth_request, :timestamp

      def_delegator :@auth_request, :host

      def_delegator :@auth_request, :request_signature

      def_delegator :@auth_request, :content_hash

      def_delegator :@auth_request, :request

      include Mixlib::Authentication::SignedHeaderAuth
      extend Mixlib::Authentication::OverloadDuckTape

      V1_2_SUPPORTED_DIGESTER_ALGORITHMS = ['SHA1','MD5'].freeze
      
      def initialize(request=nil)
        @auth_request = HTTPAuthenticationRequest.new(request) if request

        @valid_signature, @valid_timestamp, @valid_content_hash = false, false, false

        @hashed_body = nil
      end


      def authenticate_user_request(request, user_lookup, time_skew=(15*60))
        @auth_request = HTTPAuthenticationRequest.new(request)
        authenticate_request(user_lookup, time_skew)
      end

      # Takes the request, boils down the pieces we are interested in,
      # looks up the user, generates a signature, and compares to
      # the signature in the request
      # ====Headers
      #
      # X-Ops-Sign: version=1.0;
      # X-Ops-UserId: <user_id>
      # X-Ops-Timestamp:
      # X-Ops-Content-Hash: 
      # X-Ops-Authorization-#{line_number}
      def authenticate_request(user_secret, time_skew=(15*60))
        Mixlib::Authentication::Log.debug "Initializing header auth : #{request.inspect}"

        @user_secret       = user_secret
        @allowed_time_skew = time_skew # in seconds

        begin
          parts = parse_signing_description

          verify_signature(parts[:version])
          verify_timestamp
          verify_content_hash

        rescue StandardError=>se
          raise AuthenticationError,"Failed to authenticate user request. Check your client key and clock: #{se.message}", se.backtrace
        end

        if valid_request?
          SignatureResponse.new(user_id)
        else
          nil
        end
      end

      def valid_signature?
        @valid_signature
      end

      def valid_timestamp?
        @valid_timestamp
      end

      def valid_content_hash?
        @valid_content_hash
      end

      def valid_request?
        valid_signature? && valid_timestamp? && valid_content_hash?
      end

      # The authorization header is a Base64-encoded version of an RSA signature.
      # The client sent it on multiple header lines, starting at index 1 - 
      # X-Ops-Authorization-1, X-Ops-Authorization-2, etc. Pull them out and
      # concatenate.
      def headers
        @headers ||= request.env.inject({ }) { |memo, kv| memo[$2.gsub(/\-/,"_").downcase.to_sym] = kv[1] if kv[0] =~ /^(HTTP_)(.*)/; memo }
      end

      private

      def assert_required_headers_present
        MANDATORY_HEADERS.each do |header|
          unless headers.key?(header)
            raise MissingAuthenticationHeader, "required authentication header #{header.to_s.upcase} missing"
          end
        end
      end

      def_overload :verify_signature

      # Deprecate this API.
      overload_method(:verify_signature) do |algorithm, version|
        Mixlib::Authentication::Log.warn("DEPRECATED: Use the verify_signature(version) API instead.")
        verify_signature(version)
      end

      overload_method(:verify_signature) do |version|
      begin
        expected_block = canonicalize_request(version)
        signature = Base64.decode64(request_signature)

        Mixlib::Authentication::Log.debug("Verifying request signature:")

        case version
        when '1.0', '1.1'
          request_decrypted_block = @user_secret.public_decrypt(signature)
          @valid_signature = (request_decrypted_block == expected_block)

          Mixlib::Authentication::Log.debug(" Expected Block is: '#{expected_block}'")
          Mixlib::Authentication::Log.debug("Decrypted block is: '#{request_decrypted_block}'")
        when '1.2' 
          # 1. Public decrypt, result is the ASN1 encoded digest_info
          # 2. ASN1 decode digest_info, results are the digest and digest_algorithm
          # 3. Verify
          # This is documented as RSASSA-PKCS1-v1_5 signature scheme in PKCS1 v2 (http://www.ietf.org/rfc/rfc2437.txt)

          # 1. Public decrypt
          digest_info = @user_secret.public_decrypt(signature)

          # 2. ASN1 decode digest_info
          #
          # DigestInfo ::= SEQUENCE{
          #   digestAlgorithm OBJECT IDENTIFIER,
          #   digest          OCTET STRING}
          # 
          # PKCS1 v2 recommends supporting SHA1 for new applications and MD2, MD5
          # for backwards compatibility to PKCS1 v1.5. MD4 support should explicitely
          # be dropped for security reasons. The OpenSSL library does not seem to
          # support MD2 RSA signatures any more.
          #
          # Supported digest algorithms (ASN1 OID notation):
          #
          # SHA1 OBJECT IDENTIFIER ::=
          #  {iso(1) identified-organization(3) oiw(14) secsig(3)
          #   algorithms(2) 26}
          # (http://oid-info.com/get/1.3.14.3.2.26)
          #
          # MD5 OBJECT IDENTIFIER ::=
          #  {iso(1) member-body(2) US(840) rsadsi(113549)
          #   digestAlgorithm(2) 5}
          # (http://oid-info.com/get/1.2.840.113549.2.5)
          begin
            decoded_digest_info = OpenSSL::ASN1.decode(digest_info)
            digest_algorithm = decoded_digest_info.value[0].value[0].value.upcase
          rescue => e
            raise AuthenticationError, "Bad signature format, make sure to sign as specified in the RSASSA-PKCS1-v1_5 signature scheme."
          end
          Mixlib::Authentication::Log.debug("decrypted ASN.1 decoded signature : '#{decoded_digest_info.inspect}'")
          
          unless V1_2_SUPPORTED_DIGESTER_ALGORITHMS.include?(digest_algorithm)
            raise AuthenticationError, "Bad digester '#{digest_algorithm}' (allowed for protocol version 1.2: #{V1_2_SUPPORTED_DIGESTER_ALGORITHMS.inspect})"
          end

          digester = OpenSSL::Digest.const_get(digest_algorithm).new

          # 3. Verify
          @valid_signature = @user_secret.verify(digester, signature, expected_block)
        else
          raise AuthenticationError, "Bad version '#{sign_version}' (allowed: #{SUPPORTED_VERSIONS.inspect})"
        end

        Mixlib::Authentication::Log.debug("Signatures match? : '#{@valid_signature}'")

        @valid_signature
      rescue => e
        Mixlib::Authentication::Log.debug("Failed to verify request signature: #{e.class.name}: #{e.message}")
        @valid_signature = false
      end
      end #block

      def verify_timestamp
        @valid_timestamp = timestamp_within_bounds?(Time.parse(timestamp), Time.now)
      end

      def verify_content_hash
        @valid_content_hash = (content_hash == hashed_body)

        # Keep the debug messages lined up so it's easy to scan them
        Mixlib::Authentication::Log.debug("Expected content hash is: '#{hashed_body}'")
        Mixlib::Authentication::Log.debug(" Request Content Hash is: '#{content_hash}'")
        Mixlib::Authentication::Log.debug("           Hashes match?: #{@valid_content_hash}")

        @valid_content_hash
      end


      # The request signature is based on any file attached, if any. Otherwise
      # it's based on the body of the request.
      def hashed_body
        unless @hashed_body
          # TODO: tim: 2009-112-28: It'd be nice to remove this special case, and
          # always hash the entire request body. In the file case it would just be
          # expanded multipart text - the entire body of the POST.
          #
          # Pull out any file that was attached to this request, using multipart
          # form uploads.
          # Depending on the server we're running in, multipart form uploads are
          # handed to us differently. 
          # - In Passenger (Cookbooks Community Site), the File is handed to us 
          #   directly in the params hash. The name is whatever the client used, 
          #   its value is therefore a File or Tempfile. 
          #   e.g. request['file_param'] = File
          #   
          # - In Merb (Chef server), the File is wrapped. The original parameter 
          #   name used for the file is used, but its value is a Hash. Within
          #   the hash is a name/value pair named 'file' which actually 
          #   contains the Tempfile instance.
          #   e.g. request['file_param'] = { :file => Tempfile }
          file_param = request.params.values.find { |value| value.respond_to?(:read) }

          # No file_param; we're running in Merb, or it's just not there..
          if file_param.nil?
            hash_param = request.params.values.find { |value| value.respond_to?(:has_key?) }  # Hash responds to :has_key? .
            if !hash_param.nil?
              file_param = hash_param.values.find { |value| value.respond_to?(:read) } # File/Tempfile responds to :read.
            end
          end

          # Any file that's included in the request is hashed if it's there. Otherwise,
          # we hash the body.
          if file_param
            Mixlib::Authentication::Log.debug "Digesting file_param: '#{file_param.inspect}'"
            @hashed_body = digester.hash_file(file_param)
          else
            body = request.raw_post
            Mixlib::Authentication::Log.debug "Digesting body: '#{body}'"
            @hashed_body = digester.hash_string(body)
          end
        end
        @hashed_body
      end

      # Compare the request timestamp with boundary time
      # 
      # 
      # ====Parameters
      # time1<Time>:: minuend
      # time2<Time>:: subtrahend
      #
      def timestamp_within_bounds?(time1, time2)
        time_diff = (time2-time1).abs
        is_allowed = (time_diff < @allowed_time_skew)
        Mixlib::Authentication::Log.debug "Request time difference: #{time_diff}, within #{@allowed_time_skew} seconds? : #{!!is_allowed}"
        is_allowed      
      end
    end


  end
end


