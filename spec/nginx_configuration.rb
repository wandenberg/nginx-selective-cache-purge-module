module NginxConfiguration
  def self.default_configuration
    {
      :disable_start_stop_server => false,
      :master_process => 'off',
      :daemon => 'off',
      :unknown_value => nil,
      :return_code => 404
    }
  end

  def self.template_configuration
    File.open('spec/assets/nginx-test.conf').read
  end
end
