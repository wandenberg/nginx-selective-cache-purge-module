require "spec_helper"

describe "Selective Cache Purge Module Database Lock" do
  let!(:database_file) { File.join "/", "tmp", "cache.db" }
  let!(:config) { NginxConfiguration.default_configuration.merge worker_processes: 4, database_file: database_file, purge_query: "$1%"}

  before do
    File.unlink database_file if File.exists? database_file
  end

  it "should serialize database writes without losing requests" do
    number_of_requests = 5000
    nginx_run_server(config, timeout: 200) do
      requests_sent = 0
      finished = false
      EventMachine.run do
        cached_requests_timer = EventMachine::PeriodicTimer.new(0.001) do
          requests_sent += 1
          current_req_num = requests_sent
          if current_req_num > number_of_requests 
            cached_requests_timer.cancel
            EventMachine.add_timer(0.5) do
              db = SQLite3::Database.new database_file
              db.execute("select count(*) from selective_cache_purge").first.should eql [number_of_requests]
              EventMachine.stop 
            end
          else
            req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}/#{current_req_num}/index.html", connect_timeout: 10, inactivity_timeout: 15).get
            req.callback do
              fail("Request failed with error #{req.response_header.status}") if req.response_header.status != 200
            end
            req.errback do
              fail("Deu cagada!!! #{req.error}")
              EventMachine.stop
            end
          end
        end
      end
    end
  end
end