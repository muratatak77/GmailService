class OauthController < ApplicationController
  require 'google_oauth2'

  # TODO: Implement first leg of OAuth2 credential exchange here.
  def index
    redirect_to client.authorization_uri.to_s
  end

  # TODO: Implement second leg of OAuth2 credential exchange here.
  def callback
    client.code = params[:code]
    access_token_hash = client.fetch_access_token!
    Account.create_or_update(access_token_hash)
  end

  private

  def client
    @client ||= GoogleAuth2.new.client
  end
end
