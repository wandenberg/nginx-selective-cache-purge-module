require "spec_helper"

describe "Selective Cache Purge Module" do
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

  let(:number_of_files_on_cache) { 500 }

  before :each do
    File.unlink database_file if File.exists? database_file
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.mkdir_p proxy_cache_path

    Zip::ZipFile.open(File.expand_path('../spec/assets/cache.zip', File.dirname(__FILE__))) do |zipfile|
      zipfile.restore_permissions = true
      zipfile.each do |file|
        FileUtils.mkdir_p File.dirname("#{proxy_cache_path}/#{file}")
        zipfile.extract(file, "#{proxy_cache_path}/#{file}")
      end
    end
  end


  it "should be possible access the server during the load and sync process" do
    nginx_run_server(config, timeout: 200) do
      EventMachine.run do
        request_sent = 0
        request_received = 0
        timer = EventMachine::PeriodicTimer.new(0.05) do
          request_sent += 1
          req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}/index.html", connect_timeout: 10, inactivity_timeout: 15).get
          req.callback do
            fail("Request failed with error #{req.response_header.status}") if req.response_header.status != 200
            request_received += 1
          end
          req.errback do
            fail("Request failed!!! #{req.error}")
            EventMachine.stop
          end
        end

        EventMachine::PeriodicTimer.new(0.5) do
          count = db.execute("select count(*) from selective_cache_purge") rescue [[0]]
          if count[0][0] >= number_of_files_on_cache
            timer.cancel
            request_received.should be_within(5).of(request_sent)
            EventMachine.stop
          end
        end
      end
    end
  end
end
