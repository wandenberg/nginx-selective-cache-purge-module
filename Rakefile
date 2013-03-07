#!/usr/bin/env rake

require 'rake'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

nginx_dir = ENV['NGINX_SRC_DIR']
nginx_dir ||= "#{File.dirname(__FILE__)}/../nginx-1.2.7"

nginx_makefile = "#{nginx_dir}/Makefile"

def make(opts={})
  makefile_opt = opts[:makefile].nil? ? "" : "-f #{makefile}"
  puts "make #{opts[:targets].join(' ')} #{makefile_opt}"
  system "make #{opts[:targets].join(' ')} #{makefile_opt}"
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
    system "./configure --prefix=#{nginx_dir} --add-module=#{ENV['PWD']} --with-debug"
  end
end

desc "Generate makefile"
file nginx_makefile do 
  Rake::Task[:configure].invoke
end

desc "Build nginx"
task :build => [nginx_makefile] do
  chdir nginx_dir do
    system "make"
    ENV['NGINX_EXEC'] = "#{nginx_dir}/objs/nginx"
  end
end

task :rebuild => [:clean, :build]

# desc "Run tests"
task :spec => [:build]
