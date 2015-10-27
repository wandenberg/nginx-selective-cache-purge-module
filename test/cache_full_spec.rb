require File.expand_path("./spec_helper", File.dirname(__FILE__))

describe "Selective Cache Purge Module Cache Full" do
  let!(:config) do
    {
      worker_processes: 1,
      max_size: "1m",
      keys_zone: "1m"
    }
  end

  def cached_files
    Dir["#{proxy_cache_path}/**/**"].select{|path| File.file?(path)}
  end

  def rotate_cache(start=1, expected_cached_files=nil)
    initial = get_database_entries_for("*").count
    number_of_requests = expected_cached_files.nil? ? 1000 : 2 * expected_cached_files
    expected_cached_files ||= 256
    number_of_requests.times do |i|
      response_for("http://#{nginx_host}:#{nginx_port}/to/set/cache/full#{start + i}.html")
    end
    expect(cached_files.count).to be > expected_cached_files # max_size / page_size
    sleep(0.5) if NginxTestHelper.nginx_executable.include?("valgrind")
    final = get_database_entries_for("*").count
    expect(final).to eql(initial + number_of_requests)
    count = 0
    while (total = cached_files.count) > expected_cached_files # max_size / page_size
      sleep 1
      count += 1
      raise "Cache still over limit. Has #{total} files" if count > 10
    end
  end

  shared_examples_for "not found entries to purge" do
    it "should return not found" do
      nginx_run_server(config, timeout: 60) do |conf|
        rotate_cache

        expect(response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}").code).to eql('404')

        rotate_cache(1001)
      end
    end
  end

  shared_examples_for "keep redis organized" do
    it "should not have entries on redis for purged pattern" do
      nginx_run_server(config, timeout: 6000) do |conf|
        rotate_cache

        response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
        expect(get_database_entries_for(url_to_purge).count).to eql(0)

        rotate_cache(1001)
      end
    end
  end

  shared_examples_for "keep control over cache size" do
    it "should return the cache to its limit" do
      nginx_run_server(config, timeout: 60) do |conf|
        rotate_cache

        response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")

        expect{ rotate_cache(1001) }.to_not raise_error
        expect(cached_files.count).to be < 256
      end
    end
  end

  context "when purging only one entry" do

    context "and it was in cache" do
      let(:url_to_purge) { "/to/set/cache/full1000.html" }

      it "should return excluded files" do
        nginx_run_server(config, timeout: 60) do |conf|
          rotate_cache

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
          expect(resp.code).to eql('200')
          expect(resp.body).to have_purged_urls([url_to_purge])

          rotate_cache(1001)
        end
      end

      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "and it was not in cache" do
      let(:url_to_purge) { "/to/set/cache/full1.html" }

      it_should_behave_like "not found entries to purge"
      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "and it never was in cache" do
      let(:url_to_purge) { "/file_never_cached.html" }

      it_should_behave_like "not found entries to purge"
      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "reference count for cached itens" do
      it "should not keep references controlling the cache size inside its limits" do
        # to force the tries limit on function ngx_http_file_cache_forced_expire, actually in 20, we purge all files one each time
        nginx_run_server(config, timeout: 60) do |conf|
          rotate_cache

          entries = get_database_entries_for("*")
          entries.each do |cache_key, zone, type, filename|
            response_for("http://#{nginx_host}:#{nginx_port}/purge/#{cache_key}")
          end

          expect{ rotate_cache(1001) }.to_not raise_error
          expect(cached_files.count).to be < 256
        end
      end
    end
  end

  context "when purging multiple entries" do
    context "and they were in cache" do
      let(:url_to_purge) { "/to/set/cache/full99*.html" }

      it "should return excluded files" do
        nginx_run_server(config, timeout: 60) do |conf|
          rotate_cache

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
          expect(resp.code).to eql('200')
          expect(resp.body).to have_purged_urls([
            "/to/set/cache/full990.html",
            "/to/set/cache/full991.html",
            "/to/set/cache/full992.html",
            "/to/set/cache/full993.html",
            "/to/set/cache/full994.html",
            "/to/set/cache/full995.html",
            "/to/set/cache/full996.html",
            "/to/set/cache/full997.html",
            "/to/set/cache/full998.html",
            "/to/set/cache/full999.html",
          ])

          rotate_cache(1001)
        end
      end

      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "and they were not in cache" do
      let(:url_to_purge) { "/to/set/cache/full20*.html" }

      it_should_behave_like "not found entries to purge"
      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "and some were in cache and others not" do
      let(:url_to_purge) { "/to/set/cache/full74*.html" }

      it "should return excluded files" do
        nginx_run_server(config, timeout: 60000) do |conf|
          rotate_cache

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
          expect(resp.code).to eql('200')
          expect(resp.body).to have_purged_urls([
            "/to/set/cache/full746.html",
            "/to/set/cache/full747.html",
            "/to/set/cache/full748.html",
            "/to/set/cache/full749.html",
          ])

          rotate_cache(1001)
        end
      end

      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "and they never were in cache" do
      let(:url_to_purge) { "/files_never_cached*" }

      it_should_behave_like "not found entries to purge"
      it_should_behave_like "keep redis organized"
      it_should_behave_like "keep control over cache size"
    end

    context "reference count for cached itens" do
      it "should not keep references controlling the cache size inside its limits" do
        # to force the tries limit on function ngx_http_file_cache_forced_expire, actually in 20, we purge all files at once
        nginx_run_server(config, timeout: 60) do |conf|
          rotate_cache

          response_for("http://#{nginx_host}:#{nginx_port}/purge/*")

          expect{ rotate_cache(1001) }.to_not raise_error
          expect(cached_files.count).to be < 256
        end
      end
    end

    context "and there are other requests comming" do
      it "should send response to all requests" do
        nginx_run_server(config, timeout: 60) do |conf|
          rotate_cache

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
            end

            req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}/purge/*", connect_timeout: 10, inactivity_timeout: 60).get
            req.callback do
              timer.cancel
              sleep 1.5
              expect(cached_files.count).to be_within(5).of(0)
              expect(request_sent).to be > 10
              expect(request_received).to be_within(5).of(request_sent)
              EventMachine.stop
            end
          end
        end
      end
    end

    context "and the purge request is canceled" do
      context "during the scan on redis step" do
        it "should stop purging" do
          nginx_run_server(config.merge(max_size: "4m"), timeout: 60) do |conf|
            rotate_cache(1, 1024)
            initial_size = cached_files.count
            expect(initial_size).to eq 1023

            EventMachine.run do
              req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}/purge/*", inactivity_timeout: 0.008).get
              req.callback do
                fail("The request was not canceled")
                EventMachine.stop
              end
              req.errback do
                final_size = cached_files.count
                expect(final_size).to eql initial_size

                EM.add_timer(1) do
                  expect(final_size).to eql initial_size
                  EventMachine.stop
                end
              end
            end
          end
        end
      end

      context "during the purge files step" do
        it "should stop purging" do
          nginx_run_server(config.merge(max_size: "4m"), timeout: 60) do |conf|
            rotate_cache(1, 1024)
            initial_size = cached_files.count
            expect(initial_size).to eq 1023

            EventMachine.run do
              req = EventMachine::HttpRequest.new("http://#{nginx_host}:#{nginx_port}/purge/*", inactivity_timeout: 2).get
              req.callback do
                fail("The request was not canceled")
                EventMachine.stop
              end
              req.errback do
                final_size = cached_files.count
                expect(final_size).to be > 0
                expect(final_size).to be < initial_size

                EM.add_timer(1) do
                  expect(cached_files.count).to eq final_size
                  EventMachine.stop
                end
              end
            end
          end
        end
      end
    end
  end
end

