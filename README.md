Nginx Selective Cache Purge Module
==================================

A module to purge cache by GLOB patterns. The supported patterns are the same as supported by [Redis](http://redis.io/commands/KEYS).

_This module is not distributed with the Nginx source. See [the installation instructions](#installation)._


Configuration
-------------

An example:

    pid         logs/nginx.pid;
    error_log   logs/nginx-main_error.log debug;

    # Development Mode
    # master_process      off;
    # daemon              off;
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
        error_log       logs/nginx-http_error.log;

        proxy_cache_path /tmp/cache_zone levels=1:2 keys_zone=zone:10m inactive=10d max_size=100m;
        proxy_cache_path /tmp/cache_other_zone levels=1:2 keys_zone=other_zone:1m inactive=1d max_size=10m;

        #selective_cache_purge_redis_unix_socket "/tmp/redis.sock";
        #
        # or
        #
        #selective_cache_purge_redis_host "localhost";
        #selective_cache_purge_redis_port 6379;

        selective_cache_purge_redis_database 1;

        server {
            listen          8080;
            server_name     localhost;

            # purging by prefix
            location ~ /purge(.*) {
                selective_cache_purge_query "$1*";
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

            # purging by extension
            location ~ /purge/.*(\..*)$ {
                #purge by extension
                selective_cache_purge_query "*$1";
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

This module requires:
- Redis 2.8 or newer. Install it with your favourite package manager - apt-get, yum, brew - or download [Redis](http://redis.io/download) and compile it.
- hiredis 0.11.0. Install it with your favourite package manager - apt-get, yum, brew - or download [hiredis](https://github.com/redis/hiredis/releases) and compile it.
- [redis_nginx_adapter](https://github.com/wandenberg/redis_nginx_adapter) library

[Download Nginx Stable](http://nginx.org/en/download.html) source and uncompress it. You must then run ./configure with --add-module pointing to this project as usual, referencing the up-to-date hiredis/redis_nginx_adapter lib and include if they are not on your default lib and include folders. Something in the lines of:

    $ ./configure \
        --with-ld-opt='-L/usr/lib/ ' \
        --with-cc-opt='-I/usr/include/hiredis/ ' \
        --add-module=/path/to/nginx-selective-cache-purge-module
    $ make
    $ make install


Running tests
-------------

This project uses [nginx_test_helper](https://github.com/wandenberg/nginx_test_helper) on the test suite. So, after you've installed the module, you can just install the necessary gems:

    $ bundle install

And run rspec pointing to where your Nginx binary is (default: /usr/local/nginx/sbin/nginx):

    $ NGINX_EXEC=/path/to/nginx rspec spec/


Changelog
---------

This is still a work in progress. Be the change. And take a look on the [Changelog](Changelog.md).
