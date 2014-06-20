gem 'savon', '=2.5.0'

require 'digest'
require 'savon'

user_name = "neo"

#contents = File.open("tmp/somefile", "r").read

#md5sum = Digest::MD5.hexdigest(contents)

@client = Savon::Client.new do
  wsdl "http://localhost:8000/app/?wsdl"
  pretty_print_xml true
end

@response = @client.call(:authenticate) do
  message({"user_name" => user_name, "password" => "Wh1teR@bbit"})
end
