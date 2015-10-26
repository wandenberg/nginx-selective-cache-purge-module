require 'rubygems'
# Set up gems listed in the Gemfile.
ENV['BUNDLE_GEMFILE'] ||= File.expand_path('Gemfile', File.dirname(__FILE__))
require 'bundler/setup' if File.exists?(ENV['BUNDLE_GEMFILE'])
Bundler.require(:default, :test) if defined?(Bundler)

require "net/http"
require "uri"

require File.expand_path('nginx_configuration', File.dirname(__FILE__))

def proxy_cache_path
  "/tmp/cache"
end

def redis_unix_socket
  File.join(NginxTestHelper::Config.nginx_tests_tmp_dir, "selective_cache_purge_redis_test.socket")
end

def redis_host
  'localhost'
end

def redis_port
  63790
end

def redis_database
  4
end

def redis(host=redis_host, port=redis_port, database=redis_database)
  @redis ||= Redis.new(host: host, port: port, db: database, driver: :hiredis)
end

def clear_database
  redis.flushdb
end

def ttl_database_entries_for(cache_key)
  get_database_entries_for(cache_key).map do |entry|
    redis.ttl(entry.join(":"))
  end
end

def get_database_entries_for(cache_key)
  redis.scan_each(match: "#{cache_key}:*:*:*").map{ |key| key.split(":") }
end

def get_database_entries_for_zone(zone)
  redis.scan_each(match: "*:#{zone}:*:*").map{ |key| key.split(":") }
end

def insert_entry_on_database(zone, type, cache_key, filename, expires)
  redis.setex("#{cache_key}:#{zone}:#{type}:#{filename}", expires - Time.now.to_i + 1, 1)
end

def response_for(url)
  uri = URI.parse(url)
  Net::HTTP.get_response(uri)
end

RSpec::Matchers.define :have_purged_urls do |urls|
  match do |actual|
    text = actual.is_a?(Array) ? actual.map{|v| "\n#{v} ->"}.join : actual
    urls.all? do |url|
      text.match(/\n#{url} ->/)
    end
  end

  failure_message do |actual|
    "expected that #{actual} would #{description}"
  end

  failure_message_when_negated do |actual|
    "expected that #{actual} would not #{description}"
  end

  description do
    "have purged the urls: #{urls.join(", ")}"
  end
end

RSpec::Matchers.define :have_not_purged_urls do |urls|
  match do |actual|
    text = actual.is_a?(Array) ? actual.map{|v| "\n#{v} ->"}.join : actual
    urls.none? do |url|
      text.match(/\n#{url} ->/)
    end
  end

  failure_message do |actual|
    "expected that #{actual} would not #{description}"
  end

  failure_message_when_negated do |actual|
    "expected that #{actual} would #{description}"
  end

  description do
    "have purged none of the urls: #{urls.join(", ")}"
  end
end

RSpec.configure do |config|
  config.before(:suite) do
    FileUtils.mkdir_p NginxTestHelper.nginx_tests_tmp_dir
    system("redis-server --port #{redis_port} --unixsocket #{redis_unix_socket} --unixsocketperm 777 --daemonize yes --pidfile #{redis_unix_socket.gsub("socket", "pid")}")
  end

  config.after(:suite) do
    system("kill `cat #{redis_unix_socket.gsub("socket", "pid")}`")
  end

  config.before(:each) do
    clear_database
    FileUtils.chmod_R(0700, proxy_cache_path) if File.exists?(proxy_cache_path)
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.mkdir_p proxy_cache_path
  end

  config.after(:each) do
    NginxTestHelper::Config.delete_config_and_log_files(config_id) if has_passed?
    redis.quit
    @redis = nil
  end
  config.order = "random"
  config.run_all_when_everything_filtered = true
end

