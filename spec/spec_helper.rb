require 'rubygems'
require 'bundler/setup'
Bundler.require :default

require File.expand_path('nginx_configuration', File.dirname(__FILE__))

RSpec.configure do |config|
  config.treat_symbols_as_metadata_keys_with_true_values = true
  config.run_all_when_everything_filtered = true
  config.order = 'random'
end

