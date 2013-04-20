#!/usr/bin/env rake

require 'rake'

# Set up gems listed in the Gemfile.
ENV['BUNDLE_GEMFILE'] ||= File.expand_path('./Gemfile', File.dirname(__FILE__))
require 'bundler/setup' if File.exists?(ENV['BUNDLE_GEMFILE'])
Bundler.require(:default, :test) if defined?(Bundler)

begin
  require "rspec/core/rake_task"

  desc "Run all examples"
  RSpec::Core::RakeTask.new(:spec)
rescue LoadError
  task :spec do
    abort "RSpec is not available. In order to run rspec, you must: (sudo) gem install rspec"
  end
end

src_dir = File.dirname(__FILE__)

nginx_src_dir = File.expand_path(ENV['NGINX_SRC_DIR'] || "#{src_dir}/../nginx-1.2.7")
nginx_prefix_dir = File.expand_path(ENV['NGINX_PREFIX_DIR'] || "/tmp/nginx_tests/nginx")
obj_dir = File.join nginx_src_dir, "objs"

nginx_makefile = "#{nginx_src_dir}/Makefile"

def make(opts={})
  makefile_opt = opts[:makefile].nil? ? "" : "-f #{makefile}"
  sh "make #{opts[:targets].join(' ')} #{makefile_opt}"
end

task :default => :build

task :check_nginx_src_available do
  unless Dir.exists? nginx_src_dir
    puts "\nNginx sources not available at #{nginx_src_dir}.\nPlease set a valid Nginx code dir at NGINX_SRC_DIR env var.\n\n"
    exit 1
  end
end

desc "Cleans up all objects"
task :clean => [:check_nginx_src_available] do
  chdir nginx_src_dir do
    make targets: [:clean]
  end
end

desc "Configure"
task :configure => [:check_nginx_src_available] do
  chdir nginx_src_dir do
    sh "./configure --prefix=#{nginx_prefix_dir} --add-module=#{ENV['PWD']} --with-debug #{ENV["NGINX_CONFIGURE_EXTRA"]}"
  end
end

desc "Generate makefile"
file nginx_makefile do
  Rake::Task[:configure].invoke
end

file '#{obj_dir}/nginx' => [nginx_makefile] do
  chdir nginx_src_dir do
    sh "make && make install > /dev/null 2>&1"
    ENV['NGINX_EXEC'] ||= "#{nginx_prefix_dir}/sbin/nginx"
  end
end

desc "Build nginx"
task :build => ['#{obj_dir}/nginx']

desc "Rebuild nginx"
task :rebuild => [:clean, :build]

modules = FileList.new("#{obj_dir}/addon/**/*.o")

desc "Clean modules"
task :clean_modules => [nginx_makefile] do
  sh "rm -f #{modules.join(' ')}"
end

desc "Rebuild modules"
task :rebuild_modules => [:clean_modules, :build]

# desc "Run tests"
task :spec => [:build]
