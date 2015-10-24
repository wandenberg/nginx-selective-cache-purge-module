module NginxConfiguration
  def self.default_configuration
    {
      disable_start_stop_server: false,
      master_process: 'off',
      daemon: 'off',
      unknown_value: nil,
      return_code: 404,
      additional_config: '',
      worker_processes: 4,
      proxy_cache_path: "/tmp/cache",
      redis_unix_socket: nil,
      redis_host: redis_host,
      redis_database: redis_database,
      purge_query: "$1*",
      max_size: "100m",
      keys_zone: "10m"
    }
  end

  def self.template_configuration
    File.open(File.expand_path('assets/nginx-test.conf', File.dirname(__FILE__))).read
  end
end
