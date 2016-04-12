ngx.log(0,"Calling get_token.lua")
local cjson = require 'cjson'
local ts = require 'threescale_utils'

local params = {}

local function store_token(app_id, access_token, expires_in)

  ngx.log(0,"Entering the store_token function")
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. app_id ..
    "&token=".. access_token..
    "&ttl="..expires_in})

  if stored.status ~= 200 then
    ngx.log(0,"Token Could not be stored")
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.log(0,'{"access_token": "'.. access_token .. '", "expires_in": "'.. expires_in .. '","token_type": "bearer", "refresh_token": "'.. refresh_token ..'"}')
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  ngx.log(0,"Entering the get_token function")
  local auth_code_required_params = {'username', 'password','app_id'}
  ngx.log(0,"Checking and setting  parameters...") 
  if ts.required_params_present(auth_code_required_params, params)  then
  stormpath_username=params['username'];
  stormpath_password=params['password'];
  threescale_app_id=params['app_id'];
    
    ngx.log(0, "Calling oauth/token");
    local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, body = "grant_type=password&username="..stormpath_username.."&password="..stormpath_password})
    
    if res.status ~= 200 then
      ngx.log(0, "Something went wrong when retrieving the token from Stormpath");
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      ngx.log(0, "Storing token in 3scale backend");
      token = cjson.decode(res.body)
      access_token = token.access_token
      expires_in = token.expires_in
      refresh_token = token.refresh_token
      store_token(threescale_app_id, access_token, expires_in)
    end

  else
    ngx.log(0,"This function requires 3 parameters: stormpath username, stormpath password and 3scale app_id")
    ngx.log(0, "There is an error in the parameters")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

if "GET" == ngx.req.get_method() then
  params = ngx.req.get_uri_args()
else
  ngx.req.read_body()
  params = ngx.req.get_post_args()
end

-- Check valid credentials first in backend

local exists = ngx.location.capture("/_threescale/redirect_uri_matches", { vars= {app_id=params.app_id}})

if exists.status ~= 200 then
  ngx.status = 403
  ngx.header.content_type = 'text/plain; charset=us-ascii'
  ngx.print("Authentication failed")
  ngx.exit(ngx.HTTP_OK)
else
  -- Here we capture the username and passwords that the user entered in the form
  local s = get_token(params)
end


