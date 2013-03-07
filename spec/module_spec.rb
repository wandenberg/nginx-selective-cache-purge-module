require "spec_helper"
require "net/http"
require "uri"

describe "Selective Cache Purge Module" do

  let!(:database_file) { File.join ENV['PWD'], "work", "cache.db" }
  let!(:config) { NginxConfiguration.default_configuration.merge database_file: database_file}

  before do
    File.unlink database_file if File.exists? database_file
  end

  it "should create the database file" do
    nginx_test_configuration(config)
    File.exists?(database_file).should be_true
  end

  it "should fail when database file already exists but is invalid" do
    `dd if=/dev/random of=#{database_file} count=1000`
    errmsg = nginx_test_configuration(config)
    # puts errmsg
  end

  it 'should return 200 for an existing non-purge url' do
    nginx_run_server(config)  do
      uri = URI.parse("http://#{nginx_host}:#{nginx_port}/index.html")
      response = Net::HTTP.get_response(uri)
      response.code.should eq '200'

      uri = URI.parse("http://#{nginx_host}:#{nginx_port}/purge/index.html")
      response = Net::HTTP.get_response(uri)
      response.code.should eq '200'
    end
  end

  it 'should return 200 for an existing non-purge url' do
    nginx_run_server(config)  do
      uri = URI.parse("http://#{nginx_host}:#{nginx_port}/purge/index.html")
      response = Net::HTTP.get_response(uri)
      response.code.should eq '200'
    end
  end
end

