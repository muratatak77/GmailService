class String
  def normalized_email_address
    nil
  end

  alias :normalized_email_address? :normalized_email_address


  PARSED_ADDRESS_CACHE_SIZE = 5000
  NAME_FIELD_LIMITS = 255

  public

  # Strip Emoji / Unicode Basic Multilingual Plane
  def strip_emoji
    self.gsub(/[^\u0000-\uFFFF]/, '')
  end

  # Attempt to re-encode strings that aren't valid UTF-8.
  # This should hopefully deal gracefully with cp-1252/iso-8859-1.
  # The return string will be valid UTF-8 even if the input is garbage.
  def convert_unknown_to_utf8
    if encoding == Encoding::UTF_8 && valid_encoding?
      return self
    end

    detected = CharDet.detect(self)['encoding']
    detected ||= Encoding::ISO_8859_1.name
    if detected =~ /iso-8859-2/i
      detected = Encoding::ISO_8859_1.name
    end

    # If the string is utf-8, try to salvage valid utf-8 from it
    if detected.casecmp(Encoding::UTF_8.name) == 0
      begin
        return self.encode(Encoding::UTF_16, Encoding::UTF_8, :invalid => :replace, :undef => :replace ).encode(Encoding::UTF_8, :invalid => :replace, :undef => :replace )
      rescue Error::EINVAL
        return nil
      end
    end

    begin
      self.encode( Encoding::UTF_8, Mail::RubyVer.pick_encoding( detected ), :invalid => :replace, :undef => :replace )
    rescue Encoding::CompatibilityError, Encoding::ConverterNotFoundError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError, Errno::EINVAL
      nil
    end
  end

  def force_valid_utf8!
    if encoding == Encoding::UTF_8 && valid_encoding?
      return self
    end

    if encoding == Encoding::ASCII_8BIT && is_utf8?
      return force_encoding( Encoding::UTF_8 )
    end

    begin
      force_encoding( Encoding::ASCII_8BIT ).encode!( Encoding::UTF_8, :invalid => :replace, :undef => :replace )
    rescue Encoding::CompatibilityError, Encoding::ConverterNotFoundError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError, Errno::EINVAL
      nil
    end
  end

  def force_valid_utf8
    if encoding == Encoding::UTF_8 && valid_encoding?
      return self
    else
      dup.force_valid_utf8!
    end
  end

  # SB-6366 Temporary fix for watch_box_jobs deserialization error
  def instance_variable_set_with_normalize_patch(k,v)
    return if k == "normalized_email_address"
    instance_variable_set_without_normalize_patch(k,v)
  end
  alias_method_chain :instance_variable_set, :normalize_patch 

  def normalize_email_address
    x = downcase
    x.squish!
    x.gsub!(/\s/, '')
    x
  end

  alias :normalize_hostname :normalize_email_address 

  def valid_email_address?
    !parse_email_address.nil?
  end

  def valid_email_address_with_domain?
    ( address = parse_email_address ) and !address[ :host ].nil?
  end

  def valid_email_address_for_invitation?
    (address = parse_email_address) && address[:host].present? &&
      "#{address[:mailbox]}@#{address[:host]}".valid_email_address_strict?
  end

  def valid_email_address_strict?
    begin
      ValidatesEmailFormatOf.validate_email_format_without_strict( self ).nil?
    rescue Exception => e
      return false
    end
  end

  def parse_email_address()
    @@parse_cache ||= Hash.new do |hash, address|
      hash.clear if hash.size == PARSED_ADDRESS_CACHE_SIZE
      hash[address] = address.parse_email_address_without_caching
    end
    @@parse_cache[self]
  end

  # returns nil if the mailbox and host cannot be parsed.
  def parse_email_address_without_caching
    begin
      parsed = Mail::Address.new(self)
      {:name => parsed.name, :mailbox => parsed.local, :host => parsed.domain} unless parsed.address.nil?
    rescue Mail::Field::ParseError => e
      nil
    rescue ArgumentError, SyntaxError => e
      nil
    end
  end

  def parse_email_address_to_net_imap_address
    h = parse_email_address
    Net::IMAP::Address.new.tap do |a|
      a.name = h[:name]
      a.mailbox = h[:mailbox]
      a.host = h[:host]
    end if h
  end

  def contact_name_is_email_address?
    separate_names.present? && separate_names.size > 1 && separate_names.first.valid_email_address_with_domain?
  end

  def separate_first_and_last_name
    combined_name = self
    return nil if combined_name.nil?

    # strip anything between brackets (#406)
    if combined_name =~ /^([^\[]*)\[/
      front = $1.gsub(/\s+$/, '')
      if combined_name =~ /\]([^\]]*)$/
        back = $1.gsub(/^\s+/, '')
      else
        back = nil
      end
      combined_name = "#{front} #{back}"
    end

    # strip anything between parens (#424)
    if combined_name =~ /^([^\(]*)\(/
      front = $1.gsub(/\s+$/, '')
      if combined_name =~ /\)([^\)]*)$/
        back = $1.gsub(/^\s+/, '')
      else
        back = nil
      end
      combined_name = "#{front} #{back}"
    end

    # Last, First M
    if combined_name =~ /^\s*([^,]+?)\s*,\s*([^,]+?)(\s+\S+)?\s*$/
      first = $2
      middle = $3
      last = $1
      unless middle.nil?
        middle = strip_middle_name(middle)
        unless middle.nil? || middle.empty?
          first += " " + middle
        end
      end
      return nil if first.length > NAME_FIELD_LIMITS || last.length > NAME_FIELD_LIMITS
      return first, last
    # First M. Last
    elsif combined_name =~ /^\s*(\S+)\s+(.*?)(\S+)\s*$/
      first = $1
      middle = $2
      last = $3
      middle = strip_middle_name(middle)
      unless middle.nil? || middle.empty?
        first += " " + middle
      end
      return nil if first.length > NAME_FIELD_LIMITS || last.length > NAME_FIELD_LIMITS
      return first, last
    # First (we assume)
    else
      cleaned_first = combined_name.strip
      return nil if cleaned_first.length > NAME_FIELD_LIMITS
      return cleaned_first, nil
    end
  end

  def parse_first_and_last_name
    split_name = separate_first_and_last_name
    if split_name.nil?
      nil
    else
      split_name.each do |name_part|
        if name_part.nil?
          nil
        else
          name_part.strip!
        end
      end
      split_name
    end
  end

  def separate_names
    if parts = separate_first_and_last_name.try( :compact )
      parts.map{ |i| i.split( /\s+/ ) }.flatten.map do |i|
        if i.present?
          i.strip
        end
      end
    end
  end

  def from_q_encoding
    begin
      # Mail uses regexes on the input string, which blow up on non-utf8
      Mail::Encodings.unquote_and_convert_to(self.convert_unknown_to_utf8, Encoding::UTF_8 )
    rescue Encoding::CompatibilityError, Encoding::ConverterNotFoundError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError, Errno::EINVAL
      self
    end.force_valid_utf8
  end

  def capitalize_first_letter!
    self[0] = self[0].chr.capitalize
    self
  end
      
  def capitalize_first_letter
    dup.capitalize_first_letter!
  end

  def to_message_id( domain = ProductionDomain )
    "<#{self}@#{domain}>"
  end

  private
  
  def strip_middle_name(middle)
    # ignore middle initial, but not middle names (since we get better results if they're treated as part of first name)
    middle.strip!

    # we use 2 regexes so we can strip multiple initials, without being overly greedy.
    middle.gsub!(/\W\S\.?\W/, '')
    middle.gsub!(/^\S\.?$/, '')

    middle.strip!

    middle
  end

  public
  def downcase_if_needed
    string_copy = (Thread.current[:downcase] ||= String.new)
    string_copy.replace(self)
    string_copy.downcase!
    if string_copy == self
      self
    else
      string_copy.dup
    end
  end

  def downcase_with_encoding_workaround
    begin
      self.downcase_without_encoding_workaround
    rescue ArgumentError
      self.dup.tap do |working_copy|
        working_copy.force_encoding(Encoding::ASCII_8BIT)
        working_copy.downcase!
        working_copy.force_encoding(Encoding::UTF_8)
      end
    end
  end
  alias_method_chain :downcase, :encoding_workaround

  def to_crlf
    to_str.gsub(/\n|\r\n|\r/) { "\r\n" }
  end

  def to_lf
    to_str.gsub(/\n|\r\n|\r/) { "\n" }
  end

  unless method_defined?(:ascii_only?)
    # Provides all strings with the Ruby 1.9 method of .ascii_only? and
    # returns true or false
    US_ASCII_REGEXP = %Q{\x00-\x7f}
    def ascii_only?
      !(self =~ /[^#{US_ASCII_REGEXP}]/)
    end
  end

  def not_ascii_only?
    !ascii_only?
  end

  def to_bool
    return true if self == true || self =~ /\A(true|t|yes|y|1)\z/i
    return false if self == false || self.blank? || self =~ /\A(false|f|no|n|0)\z/i
    raise ArgumentError.new("invalid value for Boolean: \"#{self}\"")
  end

  # This is used by the spreedly gem. Upgrading to a newer version of the spreedly gem
  # should make it unnecessary. 
  def to_xs
    Builder::XChar.encode(self)
  end

  # Perform blank? with ascii encoding if the string contains bad utf8 data
  def blank_with_encodingfix?
    begin
      blank_without_encodingfix?
    rescue ArgumentError
      save_encoding = self.encoding
      begin
        force_encoding(Encoding::ASCII_8BIT)
        blank_without_encodingfix?
      ensure
        force_encoding(save_encoding)
      end
    end
  end
  alias_method_chain :blank?, :encodingfix

  def truncate_utf8(byte_size)
    truncated = self.convert_unknown_to_utf8
    keep_length = truncated.length
    while truncated.bytesize > byte_size
      keep_length -= 1
      truncated = self.dup if truncated.equal?(self)
      truncated.slice!(keep_length)
    end
    truncated
  end
end
