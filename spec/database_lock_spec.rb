require "spec_helper"

describe "Selective Cache Purge Module Database Lock" do
  let!(:database_file) { File.join "/", "tmp", "cache.db" }
  let!(:proxy_cache_path) { "/tmp/cache" }
  let!(:config) do
    {
      worker_processes: 4,
      proxy_cache_path: proxy_cache_path,
      database_file: database_file,
      purge_query: "$1%"
    }
  end

  let(:db) { SQLite3::Database.new database_file }

  before :each do
    File.unlink database_file if File.exists? database_file
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.mkdir_p proxy_cache_path
  end

  def run_concurrent_requests_check(number_of_requests, path = "", &block)
    requests_sent = 0
    requests_success = 0
    EventMachine.run do
      cached_requests_timer = EventMachine::PeriodicTimer.new(0.001) do
        if requests_sent >= number_of_requests
          cached_requests_timer.cancel
          sleep 1.5
          block.call unless block.nil?
          EventMachine.stop
        else
          requests_sent += 1
          req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}#{path}/#{requests_sent}/index.html", connect_timeout: 100, inactivity_timeout: 150).get
          req.callback do
            fail("Request failed with error #{req.response_header.status}") if req.response_header.status != 200
            requests_success += 1
          end
        end
      end
    end
  end

  context "serializing database writes" do
    it "should not lose requests when inserting cache entries into database" do
      nginx_run_server(config, timeout: 200) do
        number_of_requests = 200
        run_concurrent_requests_check(number_of_requests) do
          db.execute("select count(*) from selective_cache_purge").first.should eql [number_of_requests]
        end
      end
    end

    it "should not lose requests when deleting cache entries from database" do
      nginx_run_server(config, timeout: 200) do
        number_of_requests = 200
        run_concurrent_requests_check(number_of_requests) do
          run_concurrent_requests_check(number_of_requests, "/purge") do
            db.execute("select count(*) from selective_cache_purge").first.should eql [0]
          end
        end
      end
    end
  end
end
