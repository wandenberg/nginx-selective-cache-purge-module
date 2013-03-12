# Set up gems listed in the Gemfile.
ENV['BUNDLE_GEMFILE'] ||= File.expand_path('../Gemfile', File.dirname(__FILE__))
require 'bundler/setup' if File.exists?(ENV['BUNDLE_GEMFILE'])
Bundler.require(:default, :test) if defined?(Bundler)

require 'rubygems'

require File.expand_path('nginx_configuration', File.dirname(__FILE__))

RSpec.configure do |config|
  config.after(:each) do
    NginxTestHelper::Config.delete_config_and_log_files(config_id) if has_passed?
  end
  config.order = "random"
  config.treat_symbols_as_metadata_keys_with_true_values = true
  config.run_all_when_everything_filtered = true
end

