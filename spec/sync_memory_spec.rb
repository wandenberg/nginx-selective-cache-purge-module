require "spec_helper"

describe "Selective Cache Purge Module Sync Memory" do
  let!(:proxy_cache_path) { "/tmp/cache" }
  let!(:config) do
    { }
  end

  let(:number_of_files_on_cache) { 500 }

  before :each do
    clear_database
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.rm_rf Dir["#{proxy_cache_path}_2/**"]
    FileUtils.mkdir_p proxy_cache_path
    FileUtils.mkdir_p "#{proxy_cache_path}_2"

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
          count = get_database_entries_for('*').count
          if count >= number_of_files_on_cache
            timer.cancel
            request_received.should be_within(5).of(request_sent)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should sync all cache zones" do
    FileUtils.cp_r Dir["#{proxy_cache_path}/*"], "#{proxy_cache_path}_2"
    additional_config = "proxy_cache_path #{proxy_cache_path}_2 levels=1:2 keys_zone=zone2:10m inactive=10d max_size=100m loader_files=100 loader_sleep=1;"

    nginx_run_server(config.merge({additional_config: additional_config}), timeout: 200) do
      EventMachine.run do
        EventMachine::PeriodicTimer.new(0.5) do
          count = get_database_entries_for('*').count
          if count >= (2 * number_of_files_on_cache)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should clear old entries after sync" do
    insert_entry_on_database('unkown_zone', 'proxy', '/115/index.html', '/b/65/721a470787d1f40cdb6307c9108de65b', Time.now.to_i + 600)
    insert_entry_on_database('zone', 'proxy', '/old_file/index.html', '/f/26/079ed7046775b65ab8983b26750e426f', Time.now.to_i + 600)
    nginx_run_server(config, timeout: 100) do
      EventMachine.run do
        EventMachine::PeriodicTimer.new(0.5) do
          count = get_database_entries_for('*').count
          if count >= number_of_files_on_cache
            sleep 1.5
            get_database_entries_for_zone('unkown_zone').count.should eql(0)
            get_database_entries_for_zone('zone').count.should eql(number_of_files_on_cache)
            EventMachine.stop
          end
        end
      end
    end
  end
end
