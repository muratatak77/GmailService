module Encryption
  # Size of the initialization vector prepended to ciphertext.
  INITIALIZATION_VECTOR_LENGTH = 8

  def get_cipher
    OpenSSL::Cipher.new("bf-cbc")
  end
    
  def encrypt(plaintext, passphrase)
    if plaintext.nil?
      return nil
    end
    crypt = get_cipher
    crypt.encrypt
    crypt.key = Digest::SHA1.digest(passphrase)
    # Using a random iv prevents precomputed dictionary attacks.
    # The iv does not have to be secure.
    initialization_vector = OpenSSL::Random.random_bytes(INITIALIZATION_VECTOR_LENGTH)
    crypt.iv = initialization_vector
    Base64.encode64(initialization_vector + crypt.update(plaintext) + crypt.final)
  end

  def decrypt(ciphertext, passphrase)
    if ciphertext.nil?
      return nil
    end
    crypt = get_cipher
    crypt.decrypt
    crypt.key = Digest::SHA1.digest(passphrase)
    binary_text = Base64.decode64(ciphertext)
    if binary_text.length < INITIALIZATION_VECTOR_LENGTH
      raise "ciphertext too short to include initialization vector"
    end
    crypt.iv = binary_text.slice!(0..INITIALIZATION_VECTOR_LENGTH-1)
    crypt.update(binary_text) << crypt.final
  end

  extend self
end
