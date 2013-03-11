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

nginx_dir = ENV['NGINX_SRC_DIR']
nginx_dir ||= "#{src_dir}/../nginx-1.2.7"

obj_dir = File.join nginx_dir, "objs"

nginx_makefile = "#{nginx_dir}/Makefile"

def make(opts={})
  makefile_opt = opts[:makefile].nil? ? "" : "-f #{makefile}"
  puts "make #{opts[:targets].join(' ')} #{makefile_opt}"
  sh "make #{opts[:targets].join(' ')} #{makefile_opt}"
end

task :default => :build

desc "Cleans up all objects"
task :clean do
  chdir nginx_dir do
    make targets: [:clean]
  end
end

desc "Configure"
task :configure do
  chdir nginx_dir do
    sh "./configure --prefix=#{nginx_dir} --add-module=#{ENV['PWD']} --with-debug"
  end
end

desc "Generate makefile"
file nginx_makefile do 
  Rake::Task[:configure].invoke
end

file '#{obj_dir}/nginx' => [nginx_makefile] do
  chdir nginx_dir do
    sh "make"
    ENV['NGINX_EXEC'] = "#{nginx_dir}/objs/nginx"
  end
end

desc "Build nginx"
task :build => ['#{obj_dir}/nginx']

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
