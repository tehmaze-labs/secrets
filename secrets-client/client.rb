require 'base64'
require 'json'
require 'net/http'
require 'optparse'
require 'openssl'
require 'ostruct'
require 'rbnacl'
require 'securerandom'
require 'uri'

class Client
    @@OIDPrivate = "1.3.6.1.4.1.27266.11.17.2"
    @@OIDPublic  = "1.3.6.1.4.1.27266.11.17.1"
    @@PEMPrivate = "SECRETS PRIVATE KEY"
    @@PEMPublic  = "SECRETS PUBLIC KEY"

    attr_accessor :key, :keyFile, :baseURL, :caFile, :publicKey, :privateKey

    def initialize(keyFile, baseURL, caFile=nil)
        @keyFile = keyFile
        @baseURL = baseURL
        @caFile = caFile

        # Load and parse private key
        @key = Client.loadKeyFile(@@PEMPrivate, @keyFile)
        if @key.value[0].value != @@OIDPrivate
            raise Exception("Key file %s does not contain a SECRETS private key" % keyFile)
        end
        @publicKey = @key.value[1].value.force_encoding('binary')
        @privateKey = @key.value[2].value.force_encoding('binary')

        # Cleanup baseURL to have no trailing slash
        @baseURL = @baseURL.gsub(/\/+$/, '')
    end

    def self.loadKeyFile(type, file)
        keyData = File.read(file)
        derData = self.parsePEM(type, keyData)
        return OpenSSL::ASN1.decode(derData)
    end

    def self.parsePEM(type, data)
        header = '-----BEGIN %s-----' % type
        footer = '-----END %s-----' % type
        parsed = []
        keep = false
        data.split(/\n/).each do |line|
            if keep
                if line == footer
                    raise Exception("Could not decode %s PEM block" % type) unless parsed
                    return Base64.decode64(parsed.join(""))
                else
                    parsed.push line
                end
            elsif line == header
                keep = true
            end
        end
        raise Exception("Could not decode %s PEM block" % type)
    end

    def decrypt(s)
        nonce = Base64.decode64(s['nonce'])
        sender = Base64.decode64(s['sender'])
        secret = nil
        s['keys'].each do |pub, key|
            if Base64.decode64(pub) == @publicKey
                secret = Base64.decode64(key)
                break
            end
        end
        raise Exception, 'This node is not in the list of recipients' if secret == nil

        box = RbNaCl::Box.new(sender, @privateKey)
        key = box.decrypt(nonce, secret)
        box = RbNaCl::SecretBox.new(key)
        return box.decrypt(nonce, Base64.decode64(s['secret']))
    end

    def encryptTo(message, recipients)
        nonce = SecureRandom.random_bytes(24)
        key = SecureRandom.random_bytes(32)
        secret = {
            "sender" => Base64.strict_encode64(@publicKey),
            "nonce"  => Base64.strict_encode64(nonce),
            "secret" => Base64.strict_encode64(RbNaCl::SecretBox.new(key).encrypt(nonce, message)),
            "keys"   => {},
        }

        recipients.each do |pub|
            box = RbNaCl::Box.new(pub, @privateKey)
            pub = Base64.strict_encode64(pub)
            secret["keys"][pub] = Base64.strict_encode64(box.encrypt(nonce, key))
        end
        secret
    end

    def newHTTP(url)
        uri = URI.parse(@baseURL + url)
        http = Net::HTTP.new(uri.host, uri.port)
        if uri.scheme == "https"  # enable SSL/TLS
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            http.ca_file = @caFile
        end
        return [http, uri]
    end

    private :newHTTP

    def getJSON(url)
        http, uri = newHTTP(url)
        resp = http.get(uri)
        return JSON.parse(resp.body)
    end

    private :getJSON

    def putJSON(url, data)
        http, uri = newHTTP(url)
        resp = http.put(uri, JSON.dump(data))
        return JSON.parse(resp.body)
    end

    private :putJSON

    def command(command, *args)
        dispatch = {
            :cat => lambda { |*a| self.command_cat(*a) },
            :ls  => lambda { |*a| self.command_ls(*a) },
            :put => lambda { |*a| self.command_put(*a) },
        }

        if dispatch.has_key?(command)
            dispatch[command].call(*args)
        else
            raise ArgumentError, "no such command"
        end
    end

    def command_cat(group, file)
        secret = getJSON('/group/%s/data/%s/' % [group, file])
        puts decrypt(secret)
        0
    end

    def command_ls(group=nil)
        if group == nil
            getJSON('/group/').each { |g| puts g }
        else
            getJSON('/group/%s/data/' % group)['keys'].each { |g| puts g }
        end
        0
    end

    def command_put(group, file, source=nil)
        recipients = getJSON('/group/%s/' % group)
        if source == nil
            data = ARGF.read
        else
            data = File.read(source)
        end

        pubs = recipients.values.map!{ |pub| Base64.decode64(pub) }
        secret = encryptTo(data, pubs)
        putJSON('/group/%s/data/%s/' % [group, file], secret)
        0
    end
end

class CommandLineOptions
    def self.parse(args)
        options = OpenStruct.new
        options.caFile = '../testdata/secrets.pem'
        options.baseURL = 'https://localhost:6443'
        options.keyFile = 'testdata/client.box'
        OptionParser.new do |opts|
            opts.banner = "usage: %s [<options>] command [<args>]" % $0

            opts.on('-c', '--cafile CAFILE', 'CA certificates file') do |caFile|
                options.caFile = caFile
            end
            opts.on('-k', '--key KEYFILE', 'private key file') do |keyFile|
                options.keyFile = keyFile
            end
            opts.on('-u', '--url URL', 'server URL') do |baseURL|
                options.baseURL = baseURL
            end
        end.parse!(args)
        return [options, args]
    end
end

def run
    options, args = CommandLineOptions.parse(ARGV)
    client = Client.new(options.keyFile, options.baseURL, options.caFile)
    if args.length < 1
        raise ArgumentError, "need command"
    end
    command = args.shift
    return client.command(command.to_sym, *args)
end

if __FILE__ == $0
    exit run()
end
