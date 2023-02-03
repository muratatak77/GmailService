class CreateAccounts < ActiveRecord::Migration[6.1]
  def change
    create_table :accounts do |t|
      t.string :name
      t.string :email
      t.string :access_token
      t.string :scope
      t.string :refresh_token
      t.datetime :expires_at

      t.timestamps
    end
  end
end
