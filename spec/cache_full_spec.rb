require "spec_helper"

describe "Selective Cache Purge Module Cache Full" do
  let!(:proxy_cache_path) { "/tmp/cache" }
  let!(:config) do
    {
      worker_processes: 1,
      max_size: "1m",
      keys_zone: "1m"
    }
  end

  before :each do
    clear_database
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.mkdir_p proxy_cache_path
  end

  def cached_files
    Dir["#{proxy_cache_path}/**/**"].select{|path| File.file?(path)}
  end

  def rotate_cache(start=1)
    initial = get_database_entries_for("*").count
    1000.times do |i|
      response_for("http://#{nginx_host}:#{nginx_port}/to/set/cache/full#{start + i}.html")
    end
    final = get_database_entries_for("*").count
    final.should eql(initial + 1000)
    cached_files.count.should be > 256 # max_size / page_size
    count = 0
    while (total = cached_files.count) > 256 # max_size / page_size
      sleep 1
      count += 1
      raise "Cache still over limit. Has #{total} files" if count > 10
    end
  end

  shared_examples_for "not found entries to purge" do
    it "should return not found" do
      nginx_run_server(config, timeout: 60) do |conf|
        rotate_cache

        resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
        resp.code.should eql('404')

        rotate_cache(1001)
      end
    end
  end

  shared_examples_for "keep redis organized" do
    it "should not have entries on redis for purged pattern" do
      nginx_run_server(config, timeout: 6000) do |conf|
        rotate_cache

        response_for("http://#{nginx_host}:#{nginx_port}/purge#{url_to_purge}")
        get_database_entries_for(url_to_purge).count.should eql(0)

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
        cached_files.count.should be < 256
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
          resp.code.should eql('200')
          resp.body.should have_purged_urls([url_to_purge])

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
            response_for("http://#{nginx_host}:#{nginx_port}/purge/cache_key")
          end

          expect{ rotate_cache(1001) }.to_not raise_error
          cached_files.count.should be < 256
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
          resp.code.should eql('200')
          resp.body.should have_purged_urls([
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
          resp.code.should eql('200')
          resp.body.should have_purged_urls([
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
          cached_files.count.should be < 256
        end
      end
    end
  end
end

