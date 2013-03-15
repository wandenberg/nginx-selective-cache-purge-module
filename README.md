Nginx Selective Cache Purge Module
==================================

A module to purge cache by SQL LIKE patterns.

_This module is not distributed with the Nginx source. See [the installation instructions](#installation)._


Configuration
-------------

An example:

    pid         logs/nginx.pid;
    error_log   logs/nginx-main_error.log debug;

    # Development Mode
    master_process      off;
    daemon              off;
    worker_processes    1;
    worker_rlimit_core  500M;
    working_directory /tmp;
    debug_points abort;

    events {
        worker_connections  1024;
        #use                 kqueue; # MacOS
        use                 epoll; # Linux
    }

    http {
        default_type    application/octet-stream;

        access_log      logs/nginx-http_access.log;
        error_log       logs/nginx-http_error.log debug;

        proxy_cache_path /tmp/cache_zone levels=1:2 keys_zone=zone:10m inactive=10d max_size=100m;
        proxy_cache_path /tmp/cache_other_zone levels=1:2 keys_zone=other_zone:1m inactive=1d max_size=10m;

        selective_cache_purge_database "/tmp/cache.db";
        selective_cache_purge_database_cleanup_interval 5m;

        server {
            listen          8080;
            server_name     localhost;

            location ~ /purge(.*) {
                selective_cache_purge_query "$1%";
            }

            location / {
                proxy_pass http://localhost:8081;

                proxy_cache zone;
                proxy_cache_key "$uri";
                proxy_cache_valid 200 1m;
            }
        }

        server {
            listen          8090;
            server_name     localhost;

            location ~ /purge/.*\.(.*)$ {
                selective_cache_purge_query "%$1";
            }

            location / {
                proxy_pass http://localhost:8081;

                proxy_cache other_zone;
                proxy_cache_key "$uri";
                proxy_cache_valid 200 1m;
            }
        }

        server {
            listen          8081;
            server_name     localhost;

            location / {
                return 200 "requested url: $uri\n";
            }
        }
    }



<a id="installation"></a>Installation instructions
--------------------------------------------------

This module requires SQLite 3.7.15.2 or newer. Install it with your favourite package manager - apt-get, yum, brew - or [download](http://www.sqlite.org/download.html) and compile it.

You must build Nginx with your module inside. [Download Nginx Stable](http://nginx.org/en/download.html) source and uncompress it (ex.: to ../nginx). You must then run ./configure and with your --add-module pointing to this project as usual, referencing the up-to-date SQLite lib and include if they are not on your default lib and include folders. Something in the lines of:

    $ ./configure \\
        --with-ld-opt='-L/usr/local/sqlite/3.7.15.2/lib/' \\
        --with-cc-opt='-I/usr/local/sqlite/3.7.15.2/include/' \\
        --add-module=../nginx-selective-cache-purge-module \\
        --prefix=/home/user/dev-workspace/nginx
    $ make -j2
    $ make install


Running tests
-------------

This project uses [nginx_test_helper](https://github.com/wandenberg/nginx_test_helper) on the test suite. So, after you've installed the module, you can just download the necessary gems:

    $ bundle install

And run rspec pointing to where you Nginx binary is (default: /usr/local/nginx/sbin/nginx):

    $ NGINX_EXEC=../path/to/my/nginx rspec spec/

Also included in the project is a Rakefile that can be used to build nginx with only this module and run the test suite. The rake tasks can be found using the command:

    $ rake -T

To build and run rspec automatically using rake, you need to define where nginx sources are located (NGINX_SRC_DIR) and where it should be installed after built (NGINX_PREFIX_DIR, defaults to /tmp/nginx_tests/nginx):

    $ NGINX_SRC_DIR=/path/to/nginx/sources NGINX_PREFIX_DIR=/tmp/nginx_tests/nginx rake spec


Changelog
---------

This is still a work in progress. Be the change.
