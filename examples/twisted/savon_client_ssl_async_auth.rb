gem 'savon', '=2.5.0'

require 'digest'
require 'savon'

test_savon = Logger.new(File.open('tmp/test_savon.log', 'w'))

user_name = "neo"

#contents = File.open("tmp/somefile", "r").read

#md5sum = Digest::MD5.hexdigest(contents)

@client = Savon::Client.new do
  wsdl "https://localhost:8011/?wsdl"
  ssl_verify_mode :none
  ssl_version :TLSv1
  log true
  log_level :info
  logger test_savon
  pretty_print_xml true
end

@response = client.call(:authenticate) do
  message({"user_name" => user_name, "password" => "Wh1teR@bbit"})
end
