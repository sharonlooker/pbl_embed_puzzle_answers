require 'cgi'
require 'securerandom'
require 'uri'
require 'base64'
require 'json'
require 'openssl'



module LookerEmbedClient
    def self.my_secret()
        return '9d15e0e2b42656ee4d70e10a9803953422face004d7557f430e2c783eb4d3413'
    end


#     User Parameters:
    external_user_id = "embed_100"
    first_name = "Quizzy"
    last_name = "McQuizFace"
    permissions = ['see_user_dashboards', 'see_lookml_dashboards', 'access_data', 'see_looks']
    group_ids = [40]
    external_group_id = "My Fake Company"
    models = ['cs_module_pbl']
    user_attributes = {"brand_pbl" => "Columbia", "state_pbl" => "California"}
    access_filters = {}
    
#     System Wide Parameters:
    host = 'sandboxcl.dev.looker.com'
    secret = my_secret()
    session_length = 15 * 60
    force_logout_login = true
    
#     Other Settings: 
    embed_url = "/embed/dashboards/440"



    # user options
    json_external_user_id   = external_user_id.to_json
    json_first_name         = first_name.to_json
    json_last_name          = last_name.to_json
    json_permissions        = permissions.to_json
    json_models             = models.to_json
    json_group_ids          = group_ids.to_json
    json_external_group_id  = external_group_id.to_json
    json_user_attributes    = user_attributes.to_json
    json_access_filters     = access_filters.to_json

    # url/session specific options
    embed_path              = '/login/embed/' + CGI.escape(embed_url)
    json_session_length     = session_length.to_json
    json_force_logout_login = force_logout_login.to_json

    # computed options
    json_time               = Time.now.to_i.to_json
    json_nonce              = SecureRandom.hex(16).to_json

    # compute signature
    string_to_sign  = [host, embed_path, json_nonce, json_time,
                       json_session_length,json_external_user_id, json_permissions,
                       json_models,json_group_ids, json_external_group_id, json_user_attributes, json_access_filters].join("\n")

    signature = Base64.encode64(
                   OpenSSL::HMAC.digest(
                      OpenSSL::Digest.new('sha1'),
                      secret,
                      string_to_sign.force_encoding("utf-8"))).strip

    # construct query string
    query_params = {
      nonce:               json_nonce,
      time:                json_time,
      session_length:      json_session_length,
      external_user_id:    json_external_user_id,
      permissions:         json_permissions,
      models:              json_models,
      access_filters:      json_access_filters,
      user_attributes:     json_user_attributes,
      group_ids:           json_group_ids,
      external_group_id:   json_external_group_id,
      first_name:          json_first_name,
      last_name:           json_last_name,
      force_logout_login:  json_force_logout_login,
      signature:           signature
    }
    query_string = URI.encode_www_form(query_params)

    puts "https://#{host}#{embed_path}?#{query_string}"

end