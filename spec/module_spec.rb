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

  before :each do
    File.unlink database_file if File.exists? database_file
    FileUtils.rm_rf Dir["#{proxy_cache_path}/**"]
    FileUtils.mkdir_p proxy_cache_path
  end

  context "database creation" do
    it "should create the database file" do
      nginx_test_configuration(config)
      File.exists?(database_file).should be_true
    end

    context "displaying errors" do
      it "should show an error message when database file cannot be created" do
        error_config = config.merge database_file: "/path/to/missing/folder"
        nginx_test_configuration(error_config).should include "cannot open db: unable to open database file"
      end

      it "should show an error message when database file already exists but is invalid" do
        File.open(database_file, 'w') { |f| f.write "somerandomstring" }
        nginx_test_configuration(config).should include "ngx_selective_cache_purge: couldn't prepare stmt for insert: disk I/O error"
      end

    end
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
      db.execute("select * from selective_cache_purge where cache_key = '#{path}'").should be_empty
    end

    it "should save an entry after caching" do
      path = "/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '200'
      end
      db.execute("select * from selective_cache_purge where cache_key = '#{path}'").should_not be_empty
    end

    it "should be able to save an entry for status codes other than 200" do
      path = "/not-found/index.html"
      nginx_run_server(config) do
        response_for("http://#{nginx_host}:#{nginx_port}#{path}").code.should eq '404'
      end
      db.execute("select * from selective_cache_purge where cache_key = '#{path}'").should_not be_empty
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

      def prepare_cache()
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
        remaining_keys = db.execute("select cache_key from selective_cache_purge")
        remaining_keys.flatten.should have_not_purged_urls(purged_urls)
        remaining_keys.flatten.should have_purged_urls(cached_urls - purged_urls)
      end

      it "should remove the matched entries from the filesystem" do
        purged_urls = ["/index.html","/index2.html"]
        purged_files = []
        nginx_run_server(config) do
          prepare_cache
          purged_files = db.execute("select filename from selective_cache_purge where cache_key like 'index%'").flatten
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
        db.execute("select * from selective_cache_purge where cache_key = '#{path}'").should be_empty
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
      end
    end
  end
end

