class Account < ApplicationRecord
  validates :email, presence: true, on: :create
  validates_uniqueness_of :email
  has_many :messages

  def self.create_or_update(access_token_hash)
    account = parse(access_token_hash)
    account.save!
  end

  def self.parse(access_token_hash)
    account = Account.find_or_initialize_by(email: email)
    account.name = 'murat atak'
    account.access_token = access_token_hash['access_token']
    account.refresh_token = access_token_hash['refresh_token']
    account.scope = access_token_hash['scope']
    account.expires_at = Time.now + access_token_hash['expires_in']
    account
  end

  def self.email
    'muratatak77@gmail.com'
  end
end
