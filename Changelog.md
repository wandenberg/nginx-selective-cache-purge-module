### 0.5.5
- Add support to connect to redis using unix socket

### 0.5.4
- Fix scan on redis and purge files operations when purge request is canceled
- Fix to not let worker in starvation when purging multiple files
- Fix cleanup when problems occurs while checking if the file is on cache dir
- Fix build on nginx 1.3.2+
- Refactor to use redis_nginx_adapter

### 0.5.3
- Fix cleanup requests when server is restarting

### 0.5.2
- Fix purge files which are on redis but not on nginx memory or cache path, avoiding the cache size be over the limit

### 0.5.1
- Stop scan on redis if purge operation is canceled
- Ensure only one purge operation by nginx worker

### 0.5.0
- Replace sqlite by redis as db backend using async api
- Fix purge files not on memory to not receive a 'md5 colision' message
- Split memory diff and database store tasks to reduce the number of lock on cache memory
- Compare up to 10000 entries at each interaction to reduce lock time

### 0.4.1
- Fix mark old entries when working with multiple zones

### 0.4.0
- Remove shared memory lock from select query, do it only if receive a SQLITE_BUSY
- Remove old entries after sync memory with database
- Remove unnecessary 'order by', which was making select slower

### 0.3.0
- Fix when try to save on sqlite a cache entry that wasn't actually cached

### 0.2.0
- Reduce the time inside a locked area when syncing memory to database
- Fix compilation when --without-http-cache is used

### 0.1.2
- Execute select queries in a locked block to avoid receive a SQLITE_BUSY response

### 0.1.1
- Forcing sqlite to work on single thread mode

### 0.1.0
- Initial release
