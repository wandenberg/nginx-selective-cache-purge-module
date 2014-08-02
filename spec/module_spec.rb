require "spec_helper"

describe "Selective Cache Purge Module" do
  let!(:config) do
    { }
  end

  context "when caching" do
    it "should return 200 for a existing url" do
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}/index.html").code.should eq '200'
      end
    end

    it "should not save entries for locations without cache enabled" do
      path = "/no-cache/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '200'
      end
      get_database_entries_for(path).should be_empty
    end

    it "should save an entry after caching" do
      path = "/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '200'
      end
      get_database_entries_for(path).should_not be_empty
    end

    it "should save an entry for status codes other than 200" do
      path = "/not-found/index.html"
      nginx_run_server(config, timeout: 60) do |conf|
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '404'
        File.read(conf.access_log).should include("[MISS]")

        sleep 15

        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '404'
        File.read(conf.access_log).should include("[HIT]")

        sleep 20

        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '404'
        File.read(conf.access_log).should include("[EXPIRED]")
      end
      get_database_entries_for(path).should_not be_empty
    end

    it "should save an entry when backend is unavailable" do
      path = "/unavailable"
      nginx_run_server(config, timeout: 60) do |conf|
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '502'
        File.read(conf.access_log).should include("[MISS]")

        sleep 15

        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '502'
        File.read(conf.access_log).should include("[HIT]")

        sleep 20

        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '502'
        File.read(conf.access_log).should include("[MISS]")
      end
      get_database_entries_for(path).should_not be_empty
    end
  end

  context "when purging" do
    it "should return 400 when purging with an empty query" do
      nginx_run_server(config.merge(purge_query: "$1")) do
        response_for("http://#{nginx_host}:#{nginx_port}/purge").code.should eq '400'
      end
    end

    it "should return 404 when purging with a query that doesn't match any cached entry" do
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}/purge/index.html").code.should eq '404'
      end
    end

    context "with cached entries" do
      let! :cached_urls do
        [
          "/index.html",
          "/index2.html",
          "/resources/r1.jpg",
          "/resources/r2.jpg",
          "/resources/r3.jpg",
          "/some/path/index.html",
          "/resources.json"
        ]
      end

      def prepare_cache
        cached_urls.each do |url|
          response_for("http://#{nginx_host}:#{nginx_port}/#{url}")
        end
      end

      it "should remove only the matched entries from database" do
        purged_urls = ["/index.html","/index2.html"]
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
        end
        remaining_keys = get_database_entries_for('*')
        remaining_keys.flatten.should have_not_purged_urls(purged_urls)
        remaining_keys.flatten.should have_purged_urls(cached_urls - purged_urls)
      end

      it "should remove the matched entries from the filesystem" do
        purged_urls = ["/index.html","/index2.html"]
        purged_files = []
        nginx_run_server(config) do
          prepare_cache
          purged_files = get_database_entries_for('index%').flatten
          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_true
          end
          response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
        end
        purged_files.each do |f|
          File.exists?("#{proxy_cache_path}#{f}").should be_false
        end
      end

      it "should return 200 for a non-empty query" do
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge/index.html").code.should eq '200'
        end
      end

      it "should remove an entry from the database on successful purge" do
        path = "/index.html"
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge#{path}").code.should eq '200'
        end
        get_database_entries_for(path).should be_empty
      end

      it "should return a list of the removed entries after purging" do
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge/").body.should have_purged_urls(cached_urls)
        end
      end

      context "matching queries" do
        it "should return an empty list when the query does not match any entries" do
          nginx_run_server(config) do
            prepare_cache
            response_for("http://#{nginx_host}:#{nginx_port}/purge/some/random/invalid/path").body.should have_not_purged_urls(cached_urls)
          end
        end

        it "should purge only urls that match the purge query" do
          nginx_run_server(config) do
            prepare_cache
            purged_urls = ["/index.html","/index2.html"]
            response = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
            response.body.should have_purged_urls(purged_urls)
            response.body.should have_not_purged_urls(cached_urls - purged_urls)
          end
        end

        it "should purge only urls that match the purge query path" do
          nginx_run_server(config) do
            prepare_cache
            purged_urls = [
              "/resources/r1.jpg",
              "/resources/r2.jpg",
              "/resources/r3.jpg"
            ]
            response = response_for("http://#{nginx_host}:#{nginx_port}/purge/resources/")
            response.body.should have_purged_urls(purged_urls)
            response.body.should have_not_purged_urls(cached_urls - purged_urls)
          end
        end

        it "should not cause md5 collision when the isn't on memory" do
          nginx_run_server(config) do
            prepare_cache
          end

          nginx_run_server(config) do |conf|
            error_log_pre = File.readlines(conf.error_log)

            purged_urls = [
              "/resources/r1.jpg",
              "/resources/r2.jpg",
              "/resources/r3.jpg"
            ]

            response = response_for("http://#{nginx_host}:#{nginx_port}/purge/resources/")

            error_log_pos = File.readlines(conf.error_log)
            (error_log_pos - error_log_pre).join.should_not include("md5 collision")

            response.body.should have_purged_urls(purged_urls)
            response.body.should have_not_purged_urls(cached_urls - purged_urls)
          end
        end
      end
    end
  end
end

