# encoding: utf-8
require "logstash/inputs/base"
require "stud/interval"
require "socket" # for Socket.gethostname

# Generate a repeating message.
#
# This plugin is intented only as an example.

class OAuthClient

  def get_token
    raise "Not implemented!"
  end
end

class ResourceOwnerOAuthClient < OAuthClient
  def initialize(session, client_id, client_secret, email, password, logger)
    @session = session
    
    @logger = logger

    @client_id = client_id
    @client_secret = client_secret
    @email = email
    @password = password

    @token_hash = {
      expires: 0,
      response: {},
      claims: {}
    }
  end

  def get_token
    ret = self.get_token_hash

    return ret[:response]["access_token"]
  end

  def get_token_claims
    ret = self.get_token_hash

    return ret[:claims]
  end

  def get_token_hash
    now = Time.now.to_i

    expires = @token_hash[:expires]

    if expires < now
      refesh_token = @token_hash[:response]["refresh_token"]

      if refesh_token
        @logger.debug("Getting Flume API access token (from refresh token)")
        auth_body = {
          grant_type: "refresh_token",
          
          client_id: @client_id,
          client_secret: @client_secret.value,
          
          refresh_token: refresh_token
        }
      else
        @logger.debug("Getting Flume API access token (from credentials)")

        auth_body = {
          grant_type: "password",
          
          client_id: @client_id,
          client_secret: @client_secret.value,
  
          username: @email,
          password: @password.value
        }
      end
      
      auth_req = Net::HTTP::Post.new("/oauth/token")
      auth_req.body = JSON.generate(auth_body)
      auth_req["Accept"] = "application/json"
      auth_req["Content-Type"] = "application/json"
      
      auth_resp = @session.request(auth_req)

      token_resp_json = JSON.parse(auth_resp.body)

      puts token_resp_json

      unless token_resp_json["success"]
        detailed = token_resp_json["detailed"]
        
        raise "invalid response getting access token: " + detailed[0]
      end

      token_data = token_resp_json["data"][0]

      # @logger.debug("Getting Flume API access token")
      
      # token_req = Net::HTTP::Post.new("/api/v1/oauth/accesstoken")
      # token_req.body = JSON.generate({
      #   authorization: auth_resp_json["authorization"]
      # })
      # token_req["Accept"] = "application/json"
      # token_req["Content-Type"] = "application/json"
      
      # token_resp = @session.request(token_req)

      # token_resp_json = JSON.parse(token_resp.body)

      claims = self.get_token_claims_from_token(token_data["access_token"])

      @token_hash = {
        expires: claims["exp"] - 120,
        response: token_data,
        claims: claims
      }
    end

    return @token_hash
  end
  
  def get_token_claims_from_token(token)
    jwt_parts = token.split(".")

    claims_part = jwt_parts[1]

    claims_json = Base64.decode64(claims_part)

    claims = JSON.parse(claims_json)

    return claims
  end
end

class FlumeApiConnection
  def initialize(client_id, client_secret, email, password, logger)
    @session = Net::HTTP.start("api.flumewater.com", 443, use_ssl: true)
    @authenticator = ResourceOwnerOAuthClient.new(@session, client_id, client_secret, email, password, logger)
    
    @logger = logger

    @stop = false
  end

  def stop
    @stop = true
  end

  def send_request(req)
    req["Accept"] = "application/json"
    req["Authorization"] = "Bearer " + @authenticator.get_token

    resp = @session.request(req)

    resp_json = JSON.parse(resp.body)

    unless resp_json["success"]
      puts resp.to_hash

      retry_after = resp["retry-after"]

      if retry_after
        @logger.info("Rate limit reached. Waiting...", :retry_after => retry_after)
        Stud.stoppable_sleep(Integer(retry_after)) {
          @stop
        }
        return self.send_request(req)
      end
      
      raise "invalid response from '#{req.uri}': " + resp.body
    end

    return resp_json["data"]
  end

  def get_devices
    resp = self.send_request(Net::HTTP::Get.new("/me/devices?user=false&location=true"))

    return resp.select { |device|
      device["type"] == 2
    }
  end

  def get_readings_by_minute(device, to, from)
    device_id = device["id"]

    device_tz = TZInfo::Timezone.get(device["location"]["tz"])

    body = {
      queries: [
        {
          request_id: "by_minute",

          bucket: "MIN",

          units: "LITERS",

          since_datetime: device_tz.to_local(from).strftime('%Y-%m-%d %H:%M:%S'),
          until_datetime: device_tz.to_local(to).strftime('%Y-%m-%d %H:%M:%S')
        }
      ]
    }

    req = Net::HTTP::Post.new("/me/devices/#{device_id}/query")
    req.body = JSON.generate(body)
    req["Content-Type"] = "application/json"
    resp = self.send_request(req)

    ret = resp[0]["by_minute"]

    ret.select! { |item|
      item["value"] > 0
    }

    ret.map! { |item|
      item_from = device_tz.local_to_utc(DateTime.parse(item["datetime"]))
      item_to = item_from + (1.0 / (24 * 60))
      
      {
        from: item_from.to_time,
        to: item_to.to_time,
        value: {
          perMinute: {
            liters: item["value"]
          }
        }
      }
    }

    puts ret

    ret.sort_by! { |item| item[:from] }

    puts ret

    ret.pop

    puts ret

    return ret
  end

  def get_url(path, query_parameters = nil)
    unless path.start_with?("/")
        path = "/" + path
    end

    omadacid = self.get_omadacid

    url = URI("/" + omadacid + path)

    if query_parameters
        url.query = URI.encode_www_form(query_parameters)
    end

    return url.to_s
  end
end

class LogStash::Inputs::Flume < LogStash::Inputs::Base
  config_name "flume"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain"

  # The message string to use in the event.
  config :client_id, :validate => :string
  config :client_secret, :validate => :password

  config :email, :validate => :string
  config :password, :validate => :password
  
  # Set how frequently messages should be sent.
  #
  # The default, `1`, means send a message every second.
  config :interval, :validate => :number, :default => 10

  public
  def register
    @logger.info("Connecting to Flume API", :client_id => @client_id, :email => @email)
    @conn = FlumeApiConnection.new(@client_id, @client_secret, @email, @password, @logger)
  end # def register

  def run(queue)
    # we can abort the loop if stop? becomes true
    time_by_device = {}
    
    while !stop?
      now = DateTime.now
      
      @logger.debug("Getting devices from Flume API")
      devices = @conn.get_devices

      devices.each { |device|
        device_id = device["id"]
        
        since = time_by_device[device_id]

        unless since
          # since = now - 0.5
          since = now - 0.01
        end

        @logger.debug("Getting latest values from Flume API", :device_id => device_id, :since => since.iso8601)

        readings_by_minute = @conn.get_readings_by_minute(device, now, since)

        puts JSON.generate(readings_by_minute)
        
        unless readings_by_minute.empty?
          time_by_device[device_id] = readings_by_minute.map { |v| v[:to] }.max
    
          readings_by_minute.each { |reading|
            flume = {
              device: device,
              reading: reading
            }

            event = LogStash::Event.new("@timestamp" => reading[:to].to_time, "flume" => flume)
            decorate(event)
            queue << event
          }
        end
      }
    
      # because the sleep interval can be big, when shutdown happens
      # we want to be able to abort the sleep
      # Stud.stoppable_sleep will frequently evaluate the given block
      # and abort the sleep(@interval) if the return value is true
      Stud.stoppable_sleep(@interval) { stop? }
    end # loop
  end # def run

  def stop
    @conn.stop
  end
end # class LogStash::Inputs::Airthings
