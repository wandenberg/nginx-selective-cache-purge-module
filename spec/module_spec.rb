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

    it "should ignore when response is not cacheable" do
      path = "/cookie/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '200'
      end
      get_database_entries_for(path).should be_empty
      Dir["#{proxy_cache_path}/*"].should be_empty
    end

    it "should ignore when request match cache bypass" do
      path = "/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}?nocache=1").code.should eq '200'
      end
      get_database_entries_for(path).should be_empty
      Dir["#{proxy_cache_path}/*"].should be_empty
    end

    it "should save using an unix socket" do
      path = "/index.html"
      nginx_run_server(config.merge(redis_host: nil, redis_unix_socket: redis_unix_socket)) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '200'
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
      let!(:cached_urls) do
        [
          "/index.html",
          "/index2.html",
          "/resources.json",
          "/resources/r1.jpg",
          "/resources/r2.jpg",
          "/resources/r3.jpg",
          "/some/path/index.html",
        ]
      end

      def prepare_cache
        cached_urls.each do |url|
          response_for(File.join("http://#{nginx_host}:#{nginx_port}", url))
        end
      end

      it "should remove only matched entries" do
        purged_urls = ["/index.html","/index2.html"]

        nginx_run_server(config) do
          prepare_cache
          purged_files = get_database_entries_for('/index%').map{ |entry| entry[-1] }

          purged_files.count.should eq 2
          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_true
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
          resp.code.should eq '200'
          resp.body.should have_purged_urls(purged_urls)

          get_database_entries_for('/index%').should be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          remaining_keys.should eql(cached_urls - purged_urls)

          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_false
          end
        end
      end

      it "should remove only exact entry" do
        path = "/index.html"

        nginx_run_server(config) do
          prepare_cache
          purged_files = get_database_entries_for(path).map{ |entry| entry[-1] }

          purged_files.count.should eq 1
          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_true
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{path}")
          resp.code.should eq '200'
          resp.body.should have_purged_urls([path])

          get_database_entries_for(path).should be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          remaining_keys.should eql(cached_urls - [path])

          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_false
          end
        end
      end

      it "should return an empty list when the query does not match any entries" do
        nginx_run_server(config) do
          prepare_cache
          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/some/random/invalid/path")
          resp.code.should eq '404'
          resp.body.should eq "Could not found any entry that match the expression: /some/random/invalid/path*\n"
        end
      end

      it "should not cause md5 collision when nginx memory is empty" do
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

      it "should remove using an unix socket" do
        purged_urls = ["/index.html","/index2.html"]

        nginx_run_server(config.merge(redis_host: nil, redis_unix_socket: redis_unix_socket)) do
          prepare_cache
          purged_files = get_database_entries_for('/index%').map{ |entry| entry[-1] }

          purged_files.count.should eq 2
          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_true
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
          resp.code.should eq '200'
          resp.body.should have_purged_urls(purged_urls)

          get_database_entries_for('/index%').should be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          remaining_keys.should eql(cached_urls - purged_urls)

          purged_files.each do |f|
            File.exists?("#{proxy_cache_path}#{f}").should be_false
          end
        end
      end

      context "and fail to remove file from the filesystem" do
        it "should ignore the missing entries but clear it from database" do
          nginx_run_server(config) do
            prepare_cache
            purged_files = get_database_entries_for('*')
            purged_files.each do |entry|
              File.exists?("#{proxy_cache_path}#{entry[-1]}").should be_true
            end

            # change directory of /index2.html to be read only
            FileUtils.chmod(0600, File.dirname("#{proxy_cache_path}/4/37"))

            # remove the file of /some/path/index.html from disk
            FileUtils.rm("#{proxy_cache_path}/6/93/9b06947cef9c730a57392e1221d3a936")
            File.exists?("#{proxy_cache_path}/6/93/9b06947cef9c730a57392e1221d3a936").should be_false

            resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/*index*")
            resp.code.should eq '200'
            resp.body.should have_purged_urls(["/index.html"])

            # change directory to original
            FileUtils.chmod(0700, File.dirname("#{proxy_cache_path}/4/37"))
          end

          # change directory of /resources/r2.jpg to be read only
          FileUtils.chmod(0600, File.dirname("#{proxy_cache_path}/9/e9"))

          # remove the file of /resources/r1.jpg from disk
          FileUtils.rm("#{proxy_cache_path}/5/32/e121c6da57be48c3f112adf6a8e54325")
          File.exists?("#{proxy_cache_path}/5/32/e121c6da57be48c3f112adf6a8e54325").should be_false

          nginx_run_server(config.merge(worker_processes: 1), timeout: 600) do
            resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/resources*")
            resp.code.should eq '200'
            resp.body.should have_purged_urls(["/resources/r3.jpg", "/resources.json"])
          end

          # change directory to original
          FileUtils.chmod(0700, File.dirname("#{proxy_cache_path}/9/e9"))

          remaining_keys = get_database_entries_for('*')
          remaining_keys.map{|k| k[0]}.sort.should eq ["/index2.html", "/resources/r2.jpg"]

          remaining_files = Dir["#{proxy_cache_path}/**/**"].select{|f| File.file?(f)}.map{|f| f.gsub(proxy_cache_path, "") }.sort
          remaining_files.should eq ["/4/37/893f012e35119c29787435670250b374", "/9/e9/2dd79c7d48e8dc92e4dfce4e3f638e99"]
        end
      end
    end
  end
end

