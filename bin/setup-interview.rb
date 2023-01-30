#!/usr/bin/env ruby

require 'rubygems'
require 'bundler'

Bundler.setup
Bundler.require(:default)
Bundler.require(:setup)

require 'octokit'
require 'optparse'
require 'mail'

options = {
  :email => nil,
  :password => nil,
  :in_reply_to => nil,
  :subject => nil,
  :username => nil,
  :from => "#{ENV['USER']}@sanebox.com",
}

OptionParser.new do |opts|
  opts.on( '--email STRING', String, 'Setup repository for <email>' ) do |email|
    options[:email] = email
  end
  opts.on( '--username STRING', String, 'GitHub Username to invite') do |username|
    options[:username] = username
  end
  opts.on( '--from', String, "Set From Address. (Default #{options[:from]})") do |from|
    options[:from] = from
  end
  opts.on( '--in-reply-to STRING', String, 'Specify In-Reply-To for email' ) do |message_id|
    options[:in_reply_to] = message_id
  end
  opts.on( '--subject STRING', String, 'Specify subject for email' ) do |subject|
    options[:subject] = subject
  end
end.parse!

unless options[:email]
  puts "email is required"
  exit 1
end

unless options[:username]
  puts "username is required"
  exit 1
end

email_url = options[:username].gsub( /\W+/, '-' )

unless ENV['OP_SESSION_sanebox']
  puts "Ensure you have the 1Password CLI tool installed. https://support.1password.com/command-line-getting-started/"
  puts
  puts "Then run:"
  puts
  puts "  eval $(op signin sanebox.1password.com $USER@sanebox.com)"
  puts "Or:"
  puts "  eval $(op signin sanebox.1password.com)"
  puts 
  exit 1
end

# q7gi6rz4hfd2hd2hgwb25artzm is the UUID of the Secure Note in the `Secure` Vault.
access_token = IO.popen(['op', 'get', 'item', '--fields', 'password', 'su37df67bbhnvlbzlxnauu2kbu']).read.chomp 
raise "Could not get 'GitHub Interview Credentials' from 1password" unless access_token.present?
smtp_credentials = MultiJson.load(IO.popen(['op', 'get', 'item', '--fields', 'username,password', 'ktpvkiv2xjdh3chdpbil66llri']).read)
raise "Could not get 'AuthSMTP SMTP Credentials' from 1password" unless smtp_credentials.present?

github = Octokit::Client.new(access_token: access_token)

# verify username actually exists, this will raise if it doesn't
print "Verifying Github username"
user = github.user(options[:username])
puts "."

repo = nil
begin
  repo = github.repo("sanebox/interview-#{email_url}")
rescue Octokit::NotFound
  print "Creating repository from template"
  repo = github.create_repo_from_template(
    'sanebox/engineering-interview-test',
    "interview-#{email_url}", 
    owner: "sanebox",
    description: "SaneBox Engineering Interview Repository for #{options[:email]}",
    private: true,
    include_all_branches: false,
    accept: Octokit::Preview::PREVIEW_TYPES[:template_repositories]
  )
  puts "."
end

# verify that the new repository exists
repo = github.repo(repo[:full_name])

print "Inviting #{user[:login].inspect} to #{repo[:full_name]}"
invite = github.invite_user_to_repo(repo[:full_name], user[:login])
puts "."

require 'mail'
Mail.defaults do
  delivery_method :smtp,
    address: 'mail.authsmtp.com',
    port: 2525,
    authentication: :plain,
    user_name: smtp_credentials['username'],
    password: smtp_credentials['password'],
    domain: 'sanebox.com',
    enable_starttls_auto: true
end

Mail.deliver do
  from options[:from]
  cc 'careers3@sanebox.com'
  to options[:email]
  in_reply_to options[:in_reply_to]
  subject options[:subject] || 'Your SaneBox Interview'

  html_part do
    content_type 'text/html; charset=UTF-8'
    content_transfer_encoding 'quoted-printable'
    body Redcarpet::Markdown.new( Redcarpet::Render::HTML ).render( File.read( 'README.md' ) % [ email_url: email_url ] )
  end
end
