Rails.application.routes.draw do
  get 'google/oauth2' => 'oauth#index', as: :google_oauth
  get 'google/oauth2/callback' => 'oauth#callback', as: :google_oauth_callback

  root to: 'messages#index'
end
