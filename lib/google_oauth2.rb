class GoogleOauth2
  attr_accessor :client, :identity, :authenticated_client

  def initialize(account = nil)
    @account = account
  end

  def authenticated_client
    return nil unless @account

    authenticated_client = Google::Auth::UserRefreshCredentials.new(
      client_id: secrets.id,
      client_secret: secrets.secret,
      redirect_uri: 'http://localhost:3000/google/oauth2/callback',
      scope: @account.scope,
      access_token: @account.access_token,
      refresh_token: @account.refresh_token,
      expires_at: @account.expires_at
    )
  end

  def identity(email, name)
    puts "Calling identity : #{email} / Name : #{name}"
    identity = MultiJson.load(
      authenticated_client.fetch_protected_resource(
        uri: 'https://people.googleapis.com/v1/people/me?personFields=emailAddresses&resourceName=people/me'
      ).body
    )
  end

  def client
    @client ||= Google::Auth::UserRefreshCredentials.new(
      client_id: secrets.id,
      client_secret: secrets.secret,
      redirect_uri: 'http://localhost:3000/google/oauth2/callback',
      scope: 'https://www.googleapis.com/auth/gmail.readonly openid email profile'
    )
  end

  private

  def secrets
    @secrets ||= Google::Auth::ClientId.from_file(
      Rails.root.join('config/client_secret.json')
    )
  end
end
