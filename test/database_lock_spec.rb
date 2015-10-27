require File.expand_path("./spec_helper", File.dirname(__FILE__))

describe "Selective Cache Purge Module Database Lock" do
  let!(:config) do
    { }
  end

  def run_concurrent_requests_check(number_of_requests, path = "", &block)
    requests_sent = 0
    requests_success = 0
    EventMachine.run do
      cached_requests_timer = EventMachine::PeriodicTimer.new(0.001) do
        if requests_sent >= number_of_requests
          if requests_success >= requests_sent
            cached_requests_timer.cancel
            sleep 1.5
            block.call unless block.nil?
            EventMachine.stop
          end
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
          expect(get_database_entries_for('*').count).to eql(number_of_requests)
        end
      end
    end

    it "should not lose requests when deleting cache entries from database" do
      nginx_run_server(config, timeout: 200) do
        number_of_requests = 200
        run_concurrent_requests_check(number_of_requests) do
          run_concurrent_requests_check(number_of_requests, "/purge") do
            expect(get_database_entries_for('*').count).to eql(0)
          end
        end
      end
    end
  end
end
