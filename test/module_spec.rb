require File.expand_path("./spec_helper", File.dirname(__FILE__))

describe "Selective Cache Purge Module" do
  let!(:config) do
    { }
  end

  context "when caching" do
    it "should return 200 for a existing url" do
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}/index.html").code).to eq '200'
      end
    end

    it "should not save entries for locations without cache enabled" do
      path = "/no-cache/index.html"
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '200'
      end
      expect(get_database_entries_for(path)).to be_empty
    end

    it "should save an entry after caching" do
      path = "/index.html"
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '200'
      end
      expect(get_database_entries_for(path)).not_to be_empty
    end

    it "should save an entry for status codes other than 200" do
      path = "/not-found/index.html"
      nginx_run_server(config, timeout: 60) do |conf|
        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '404'
        end).to include("[MISS]")

        sleep 15

        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '404'
        end).to include("[HIT]")

        sleep 20

        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '404'
        end).to include("[EXPIRED]")
      end
      expect(get_database_entries_for(path)).not_to be_empty
    end

    it "should save an entry when backend is unavailable" do
      path = "/unavailable"
      nginx_run_server(config, timeout: 60) do |conf|
        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '502'
        end).to include("[MISS]")

        sleep 15

        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '502'
        end).to include("[HIT]")

        sleep 20

        expect(log_changes_for(conf.access_log) do
          expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '502'
        end).to include("[MISS]")
      end
      expect(get_database_entries_for(path)).not_to be_empty
    end

    it "should ignore when response is not cacheable" do
      path = "/cookie/index.html"
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '200'
      end
      expect(get_database_entries_for(path)).to be_empty
      expect(Dir["#{proxy_cache_path}/*"]).to be_empty
    end

    it "should ignore when request match cache bypass" do
      path = "/index.html"
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}?nocache=1").code).to eq '200'
      end
      expect(get_database_entries_for(path)).to be_empty
      expect(Dir["#{proxy_cache_path}/*"]).to be_empty
    end

    it "should save using an unix socket" do
      path = "/index.html"
      nginx_run_server(config.merge(redis_host: nil, redis_unix_socket: redis_unix_socket)) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}#{path}").code).to eq '200'
      end
      expect(get_database_entries_for(path)).not_to be_empty
    end

    it "should use the cache time or the inactive time as expires which is bigger" do
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}/index.html").code).to eq '200'
        expect(response_for("http://#{nginx_host}:#{nginx_port}/big-cache").code).to eq '200'
        expect(response_for("http://#{nginx_host}:#{nginx_port}/small-cache").code).to eq '200'
      end
      expect(ttl_database_entries_for("/index.html").first).to  be_within(5).of(10 * 24 * 60 * 60)
      expect(ttl_database_entries_for("/big-cache").first).to   be_within(5).of(30 * 24 * 60 * 60)
      expect(ttl_database_entries_for("/small-cache").first).to be_within(5).of(10 * 24 * 60 * 60)
    end

    it "should update the entry each time the cache is not HIT, including STALE" do
      path = "/conditional/index.html"
      nginx_run_server(config.merge(inactive: "20s"), timeout: 60) do |conf|
        expect((resp = response_for("http://#{nginx_host}:#{nginx_port}#{path}")).code).to eq '200'
        expect(resp['x-cache-status']).to include("MISS")
        sleep 1
        expect(ttl_database_entries_for(path).first).to be_within(2).of(20)

        sleep 4

        expect((resp = response_for("http://#{nginx_host}:#{nginx_port}#{path}")).code).to eq '200'
        expect(resp['x-cache-status']).to include("HIT")
        sleep 1
        expect(ttl_database_entries_for(path).first).to be_within(2).of(15)

        sleep 7

        expect((resp = response_for("http://#{nginx_host}:#{nginx_port}#{path}?error=1")).code).to eq '200'
        expect(resp['x-cache-status']).to include("STALE")
        sleep 1
        expect(ttl_database_entries_for(path).first).to be_within(2).of(20)

        sleep 1

        expect((resp = response_for("http://#{nginx_host}:#{nginx_port}#{path}")).code).to eq '200'
        expect(resp['x-cache-status']).to include("EXPIRED")
        sleep 1
        expect(ttl_database_entries_for(path).first).to be_within(2).of(20)

        sleep 9

        expect((resp = response_for("http://#{nginx_host}:#{nginx_port}#{path}")).code).to eq '200'
        expect(resp['x-cache-status']).to include("HIT")
        sleep 1
        expect(ttl_database_entries_for(path).first).to be_within(2).of(10)
      end
    end
  end

  context "when purging" do
    it "should return 400 when purging with an empty query" do
      nginx_run_server(config.merge(purge_query: "$1")) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}/purge").code).to eq '400'
      end
    end

    it "should return 404 when purging with a query that doesn't match any cached entry" do
      nginx_run_server(config) do
        expect(response_for("http://#{nginx_host}:#{nginx_port}/purge/index.html").code).to eq '404'
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
        sleep(0.5) if NginxTestHelper.nginx_executable.include?("valgrind")
      end

      it "should remove only matched entries" do
        purged_urls = ["/index.html","/index2.html"]

        nginx_run_server(config) do
          prepare_cache
          purged_files = get_database_entries_for('/index*').map{ |entry| entry[-1] }

          expect(purged_files.count).to eq 2
          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_truthy
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
          expect(resp.code).to eq '200'
          expect(resp.body).to have_purged_urls(purged_urls)

          expect(get_database_entries_for('/index*')).to be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          expect(remaining_keys).to eql(cached_urls - purged_urls)

          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_falsey
          end
        end
      end

      it "should remove only exact entry" do
        path = "/index.html"

        nginx_run_server(config) do
          prepare_cache
          purged_files = get_database_entries_for(path).map{ |entry| entry[-1] }

          expect(purged_files.count).to eq 1
          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_truthy
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge#{path}")
          expect(resp.code).to eq '200'
          expect(resp.body).to have_purged_urls([path])

          expect(get_database_entries_for(path)).to be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          expect(remaining_keys).to eql(cached_urls - [path])

          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_falsey
          end
        end
      end

      it "should return an empty list when the query does not match any entries" do
        nginx_run_server(config) do
          prepare_cache
          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/some/random/invalid/path")
          expect(resp.code).to eq '404'
          expect(resp.body).to eq "Could not found any entry that match the expression: /some/random/invalid/path*\n"
        end
      end

      it "should not cause md5 collision when nginx memory is empty" do
        nginx_run_server(config) do
          prepare_cache
        end

        nginx_run_server(config) do |conf|
          expect(log_changes_for(conf.error_log) do
            purged_urls = [
              "/resources/r1.jpg",
              "/resources/r2.jpg",
              "/resources/r3.jpg"
            ]

            response = response_for("http://#{nginx_host}:#{nginx_port}/purge/resources/")
            expect(response.body).to have_purged_urls(purged_urls)
            expect(response.body).to have_not_purged_urls(cached_urls - purged_urls)

          end).not_to include("md5 collision")
        end
      end

      it "should remove using an unix socket" do
        purged_urls = ["/index.html","/index2.html"]

        nginx_run_server(config.merge(redis_host: nil, redis_unix_socket: redis_unix_socket)) do
          prepare_cache
          purged_files = get_database_entries_for('/index*').map{ |entry| entry[-1] }

          expect(purged_files.count).to eq 2
          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_truthy
          end

          resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
          expect(resp.code).to eq '200'
          expect(resp.body).to have_purged_urls(purged_urls)

          expect(get_database_entries_for('/index*')).to be_empty
          remaining_keys = get_database_entries_for('*').map{ |entry| entry[0] }.sort
          expect(remaining_keys).to eql(cached_urls - purged_urls)

          purged_files.each do |f|
            expect(File.exists?("#{proxy_cache_path}#{f}")).to be_falsey
          end
        end
      end

      context "and fail to remove file from the filesystem" do
        it "should ignore the missing entries but clear it from database" do
          nginx_run_server(config) do
            prepare_cache
            purged_files = get_database_entries_for('*')
            purged_files.each do |entry|
              expect(File.exists?("#{proxy_cache_path}#{entry[-1]}")).to be_truthy
            end

            # change directory of /index2.html to be read only
            FileUtils.chmod(0600, File.dirname("#{proxy_cache_path}/4/37"))

            # remove the file of /some/path/index.html from disk
            FileUtils.rm("#{proxy_cache_path}/6/93/9b06947cef9c730a57392e1221d3a936")
            expect(File.exists?("#{proxy_cache_path}/6/93/9b06947cef9c730a57392e1221d3a936")).to be_falsey

            resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/*index*")
            expect(resp.code).to eq '200'
            expect(resp.body).to have_purged_urls(["/index.html"])

            # change directory to original
            FileUtils.chmod(0700, File.dirname("#{proxy_cache_path}/4/37"))
          end

          # change directory of /resources/r2.jpg to be read only
          FileUtils.chmod(0600, File.dirname("#{proxy_cache_path}/9/e9"))

          # remove the file of /resources/r1.jpg from disk
          FileUtils.rm("#{proxy_cache_path}/5/32/e121c6da57be48c3f112adf6a8e54325")
          expect(File.exists?("#{proxy_cache_path}/5/32/e121c6da57be48c3f112adf6a8e54325")).to be_falsey

          nginx_run_server(config.merge(worker_processes: 1), timeout: 600) do
            resp = response_for("http://#{nginx_host}:#{nginx_port}/purge/resources*")
            expect(resp.code).to eq '200'
            expect(resp.body).to have_purged_urls(["/resources/r3.jpg", "/resources.json"])
          end

          # change directory to original
          FileUtils.chmod(0700, File.dirname("#{proxy_cache_path}/9/e9"))

          remaining_keys = get_database_entries_for('*')
          expect(remaining_keys.map{|k| k[0]}.sort).to eq ["/index2.html", "/resources/r2.jpg"]

          remaining_files = Dir["#{proxy_cache_path}/**/**"].select{|f| File.file?(f)}.map{|f| f.gsub(proxy_cache_path, "") }.sort
          expect(remaining_files).to eq ["/4/37/893f012e35119c29787435670250b374", "/9/e9/2dd79c7d48e8dc92e4dfce4e3f638e99"]
        end
      end
    end
  end
end

