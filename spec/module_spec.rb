require "spec_helper"
require "net/http"
require "uri"

def response_for(url)
  uri = URI.parse(url)
  Net::HTTP.get_response(uri)
end

describe "Selective Cache Purge Module" do

  let!(:database_file) { File.join ENV['PWD'], "work", "cache.db" }
  let!(:config) { NginxConfiguration.default_configuration.merge database_file: database_file, purge_query: "$1%"}

  context "database creation" do
    before :each do
      File.unlink database_file if File.exists? database_file
    end

    it "should create the database file" do
      nginx_test_configuration(config)
      File.exists?(database_file).should be_true
    end

    it "should show an error message when database file already exists but is invalid" do
      File.open(database_file, 'w') { |f| f.write "muthafucka" }
      nginx_test_configuration(config).should include ("ngx_selective_cache_purge: couldn't prepare stmt for insert: disk I/O error")
    end
  end

  context "when caching" do
    before do
      File.unlink database_file if File.exists? database_file
    end

    it "should return 200 for a existing url" do
      nginx_run_server(config)  do
        response_for("http://#{nginx_host}:#{nginx_port}/index.html").code.should eq '200'
      end
    end

    xit "should save an entry after caching"

    xit "should not save a url that returns not found" do
      nginx_run_server(config)  do
        response_for("http://#{nginx_host}:#{nginx_port}/not-found/index.html").code.should eq '404'
      end
    end
  end

  context "when purging" do
    before :each do
      File.unlink database_file if File.exists? database_file
    end

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

      it "should return 200 for a non-empty query" do
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge/index.html").code.should eq '200'
        end
      end

      it "should return a list of the removed entries after purging" do
        nginx_run_server(config) do
          prepare_cache
          response_for("http://#{nginx_host}:#{nginx_port}/purge/").body.should include(*cached_urls)
        end
      end

      context "matching queries" do
        it "should return an empty list when the query does not match any entries" do
          nginx_run_server(config) do
            prepare_cache
            response_for("http://#{nginx_host}:#{nginx_port}/purge/tabaco").body.should_not include(*cached_urls)
          end
        end

        it "should purge only urls that match the purge query" do
          nginx_run_server(config) do
            prepare_cache
            purged_urls = [
              "/index.html",
              "/index2.html"
            ]
            response = response_for("http://#{nginx_host}:#{nginx_port}/purge/index")
            response.body.should include(*purged_urls)
            response.body.should_not include(*(cached_urls - purged_urls))
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
            response.body.should include(*purged_urls)
            response.body.should_not include(*(cached_urls - purged_urls))
          end
        end
      end
    end
  end
end

