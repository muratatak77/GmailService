require 'net/imap'
require 'timeout'
require 'deflate_socket'

module ImapMixin
  def get_exists_and_expunge_count
    # Get expunges and the current EXISTS count
    noop
    exists_responses = responses["EXISTS"]
    if exists_responses.nil? || exists_responses.last.nil?
      raise "Never received an EXISTS response from server,no mailbox selected ?" 
    end
    expunge_responses = responses["EXPUNGE"] || []
    {:exists => exists_responses.last, :expunge => expunge_responses.size}
  end

  # Add class variables and methods to the including class.
  # This makes it easier to unit test.
  def self.included(base)
    base.instance_eval do
      # NOTE: These class variables are shared by any class including ImapMixin,
      # despite the instance_eval.
      @@uid_validity_by_mailbox ||= {}
      @@uid_validity_checks_enabled = false

      def set_enable_uid_validity_checks(enabled)
        @@uid_validity_checks_enabled = enabled
      end

      def uid_validity_checks_enabled?
        @@uid_validity_checks_enabled
      end

      def clear_uid_validity_values
        @@uid_validity_by_mailbox.clear
      end

      def get_uidvalidity_of(mailbox)
        old_uid_validity = @@uid_validity_by_mailbox[mailbox]
      end
    end

    # Returns the uid_validity seen for the current mailbox
    def uid_validity
      @uid_validity
    end

    def switch_to_deflate
      if @use_deflate && !@deflate_setup
        @sock = ::DeflateSocket.new(@sock, @read_buffer)
        @deflate_setup = true
        @read_buffer = ""
      end
    end
    private :switch_to_deflate

    def get_response_without_rails_logging
      @read_buffer = "" if @read_buffer.nil?
      buff = ""
      begin
        switch_to_deflate
        while true
          # Loop until a full line is read
          while (end_of_line_index = @read_buffer.index(Net::IMAP::CRLF)).nil?
            old_sock = @sock
            current_read = old_sock.readpartial(4096)
            if @sock != old_sock
              @sock.add_input(current_read)
              current_read = @sock.readpartial(4096)
            end
            @read_buffer += current_read
            @got_data = true
            switch_to_deflate
          end
          cut_length = end_of_line_index + Net::IMAP::CRLF.length
          s = @read_buffer.slice!(0, cut_length)
          break unless s
          buff.concat(s)
          if /\{(\d+)\}\r\n/n =~ s
            bytes_to_read = $1.to_i
            bytes_needed = bytes_to_read - @read_buffer.length
            if bytes_needed > 0
              buff.concat(@read_buffer)
              @read_buffer = ""
              s = @sock.read(bytes_needed)
              # SB-5461 Handle running out of input
              if s.nil?
                raise Net::IMAP::ResponseParseError.new("Ran out of input")
              end
              buff.concat(s)
            else
              buff.concat(@read_buffer.slice!(0, bytes_to_read))
            end
          else
            break
          end
        end
        return nil if buff.length == 0
        if Net::IMAP.debug
          $stderr.print(buff.gsub(/^/n, "S: "))
        end
        return @parser.parse(buff)
      rescue Encoding::CompatibilityError => e
        Rails.logger.warn( "Caught Encoding::CompatibilityError when trying to parse buf: #{buff.inspect}" )
        raise
      end
    end
  end

  SELECT_RETRY_ATTEMPTS = 3
  SELECT_RETRY_SLEEP_SECONDS = 20

  # When the uidvalidity changes for a mailbox it is no longer safe to use uids
  # from that mailbox because they might refer to different messages. The
  # change can only be reported when the mailbox is selected, so we detect
  # changes between successive selects of the mailbox and abort any
  # processing in progress.
  # Also retries selecting a mailbox if we get a try again message.
  def select_with_uid_validity_checks(mailbox)
    attempts = 1
    begin
      select_without_uid_validity_checks(mailbox)
    rescue Net::IMAP::NoResponseError => no_response_error
      if attempts == SELECT_RETRY_ATTEMPTS
        altered_response = no_response_error.response.dup
        altered_response.data.text = "Could not select #{mailbox} after #{attempts} tries last response was:#{no_response_error.message}"
        raise Net::IMAP::SelectFolderFailed.new(altered_response)
      end
      if no_response_error.message =~ /Please try again later/
        sleep SELECT_RETRY_SLEEP_SECONDS
        attempts += 1
        retry
      else
        raise
      end
    rescue Net::IMAP::BadResponseError => bad_response
      if attempts == SELECT_RETRY_ATTEMPTS
        raise
      end
      sleep SELECT_RETRY_ATTEMPTS
      attempts += 1
      retry
    end

    # Select clears @responses, so there will be just one UIDVALIDITY
    @uid_validity = @responses['UIDVALIDITY'].try(:first)

    if @uid_validity.nil?
      raise "Did not get uidvalidity after select of '#{mailbox}'"
    end

    return unless self.class.uid_validity_checks_enabled?

    old_uid_validity = @@uid_validity_by_mailbox[mailbox]
    if old_uid_validity && old_uid_validity != @uid_validity
      @@uid_validity_by_mailbox.clear
      raise Net::IMAP::UidValidityChanged.new("Uid validity changed for #{mailbox}")
    end
    @@uid_validity_by_mailbox[mailbox] = @uid_validity
  end

  def flatten_search_responses(all_responses)
    return nil if all_responses.nil? || all_responses.empty?
    return all_responses.flatten
  end

  def cache_uid_validity( mailbox )
    @@uid_validity_by_mailbox[mailbox]
  end

  def get_idle_response_handler()
    @idle_response_handler ||= Proc.new do |idle_response|
      # Got EXPUNGE or EXISTS - the main thread needs to stop idle
      if idle_response.instance_of?(Net::IMAP::ContinuationRequest)
        @continuation_request = true
      elsif idle_response.instance_of?(Net::IMAP::UntaggedResponse) && idle_response.name != "OK"
        unless @idle_activity_seen
          @idle_activity_seen = true
          @activity_handler.call() if @activity_handler
        end  
      end
    end
  end

  def start_idle(activity_handler)
    response = nil
    @idle_tag = nil
    @idle_activity_seen = false
    @activity_handler = activity_handler
    synchronize do
      @idle_tag = Thread.current[:net_imap_tag] = generate_tag

      @continuation_request = nil
      add_response_handler get_idle_response_handler()
      put_string "#{@idle_tag} IDLE#{Net::IMAP::CRLF}"

      current_time = Time.now
      deadline = current_time + timeout
      until deadline <= current_time || @continuation_request || @tagged_responses.key?(@idle_tag)
        @continuation_request_arrival.wait(deadline - current_time)
        current_time = Time.now
      end

      # Entered idle mode
      if @continuation_request
        Rails.logger.debug "Got continuation request"
        @continuation_request = nil
      end

      # Any tagged responses here have to be errors
      if @tagged_responses.key?(@idle_tag)
        response = @tagged_responses.delete(@idle_tag)
        remove_response_handler get_idle_response_handler()
        @idle_tag = nil
      end # ensure
    end # synchronize

    response
  end

  def end_idle
    Rails.logger.debug "Ending idle"
    
    response = nil
    synchronize do
      put_string "DONE#{Net::IMAP::CRLF}"
      response = get_tagged_response @idle_tag, "IDLE"
      remove_response_handler get_idle_response_handler()
      @idle_tag = nil
      @idle_activity_seen = false
    end
    connection_ok = response && !response.is_a?(Net::IMAP::ResponseError)
    connection_ok
  end

  def mailbox_prefix_exists?(mailbox, mailboxes, parent_label_exist_via_delimiter = nil)
    return unless mailboxes.present?

    mailbox = mailbox.downcase + (parent_label_exist_via_delimiter || '')
    mailboxes.select { |m| m.name.downcase.start_with?(mailbox) }.presence&.map(&:name)
  end

  # returns a falsy if the mailbox doesn't exist, or an array of the *actual* names that
  # match the `mailbox` parameter (which may differ in case).
  def mailboxes_include?(mailbox, namespace_prefix: nil, exclude_empty_nested: true, parent_label_exist_via_delimiter: nil )
    namespace_prefix ||= (namespace[:personal].try(:first).try(:prefix) || '')
    mailboxes = list( namespace_prefix, '*' )
    if mailboxes.present?
      mailboxes = filter_mailbox_list(mailboxes, exclude_empty_nested: exclude_empty_nested)

      return [] unless mailboxes.present?

      # Prefer an exact match over a case-insensitive match.
      found = mailboxes.select { |m| m.name == mailbox }.presence
      found ||= mailboxes.select { |m| m.name.casecmp(mailbox) == 0 }
      val = found.presence&.map(&:name) || []

      if val.empty? && parent_label_exist_via_delimiter.present?
        val = mailbox_prefix_exists?(mailbox, mailboxes, parent_label_exist_via_delimiter) || []
      end

      val
    else
      []
    end
  end

  # returns a falsy if the mailbox doesn't exist, or the *actual* name that
  # matches the `mailbox` parameter (which may differ in case).
  def mailbox_exists?(mailbox, namespace_prefix: nil, exclude_empty_nested: true, parent_label_exist_via_delimiter: nil )
    return false if mailbox.nil?

    if mailbox.index('*').nil? && mailbox.index('%').nil?
      begin
        if mailbox.casecmp(EmailUser::INBOX_MAILBOX_NAME) == 0
          # Don't change the case of INBOX. RFC3501 indicates that INBOX is
          # case-insensitive. We want to always return what the caller expects.
          Array( list( '', mailbox ) ).detect{|list_item| list_item.name&.casecmp(EmailUser::INBOX_MAILBOX_NAME) == 0} && mailbox
        else
          namespace_prefix ||= (namespace[:personal].try(:first).try(:prefix) || '')
          filter_mailbox_list(Array( list( namespace_prefix, mailbox.sub( /\A#{Regexp.escape(namespace_prefix)}/, '' ) ) ), exclude_empty_nested: exclude_empty_nested).first&.name ||
            mailboxes_include?( mailbox, namespace_prefix: namespace_prefix, exclude_empty_nested: exclude_empty_nested, parent_label_exist_via_delimiter: parent_label_exist_via_delimiter ).presence&.first
        end
      rescue Net::IMAP::NoResponseError => resp
        # Davmail returns a no response if the folder doesn't exist
        if resp.message =~ /not found/i
          return false 
        else
          raise
        end
      end
    else
      namespace_prefix ||= (namespace[:personal].try(:first).try(:prefix) || '')
      mailboxes_include?( mailbox, namespace_prefix: namespace_prefix, exclude_empty_nested: exclude_empty_nested, parent_label_exist_via_delimiter: parent_label_exist_via_delimiter ).presence&.first
    end
  end

  def label_exists_multiple_times?(mailbox, namespace_prefix: nil, exclude_empty_nested: true, parent_label_exist_via_delimiter: nil )
    return false if mailbox.nil?

    included_in_mailboxes = []

    if mailbox.index('*').nil? && mailbox.index('%').nil?
      begin
        if mailbox.casecmp(EmailUser::INBOX_MAILBOX_NAME) == 0
          # Don't change the case of INBOX. RFC3501 indicates that INBOX is
          # case-insensitive. We want to always return what the caller expects.
          Array( list( '', mailbox ) ).select { |list_item| list_item.name&.casecmp(EmailUser::INBOX_MAILBOX_NAME) == 0 }.size > 1
        else
          namespace_prefix ||= (namespace[:personal].try(:first).try(:prefix) || '')
          included_in_mailboxes = mailboxes_include?( mailbox, namespace_prefix: namespace_prefix, exclude_empty_nested: exclude_empty_nested, parent_label_exist_via_delimiter: parent_label_exist_via_delimiter )
        end
      rescue Net::IMAP::NoResponseError => resp
        # Davmail returns a no response if the folder doesn't exist
        if resp.message =~ /not found/i
          return false
        else
          raise
        end
      end
    else
      namespace_prefix ||= (namespace[:personal].try(:first).try(:prefix) || '')
      included_in_mailboxes = mailboxes_include?( mailbox, namespace_prefix: namespace_prefix, exclude_empty_nested: exclude_empty_nested, parent_label_exist_via_delimiter: parent_label_exist_via_delimiter )
    end

    included_in_mailboxes.size > 1
  end

  # rfc2971 ID command
  def send_id(client_id)
    synchronize do
      tag = generate_tag
      # aol/yahoo won't accept the list unless the strings are double quoted and send_command
      # won't add double quotes unless necessary.
      put_string %Q[#{tag} ID ("name" "#{client_id}" "version" "1.0")#{Net::IMAP::CRLF}]
      get_tagged_response(tag, 'ID')
    end
  end

  private
  def filter_mailbox_list(mailbox_list, exclude_empty_nested:)
    mailbox_list.reject do |f|
      f.name.nil? || f.name.empty? || (exclude_empty_nested && f.attr.include?(:Noselect))
    end
  end


end # ImapMixin

module Net
  class IMAP

    remove_method :delete

    class UidValidityChanged < Exception
    end

    class ClosedConnectionError < Error
    end

    class SelectFolderFailed < ResponseError
    end

    Namespace = Struct.new(:prefix, :delim)
    def namespace
      synchronize do
        send_command("NAMESPACE")
        ResponseParser.new.parse_namespace_response(@responses.delete("NAMESPACE").first)
      end
    end

    def uid_copy(set, mailbox)
      if @is_courier.nil?
        @is_courier = (greeting.data.text =~ /Courier-IMAP/) || false
      end

      if @is_courier 
        case set
        when Integer, String
          check_folder = true
        when Array, Range
          check_folder = set.size < 2
        else
          check_folder = true
        end

        # SB-5959, SB-7134: Verify the target mailbox exists before copying.
        # currently we do this with a list.
        if check_folder && !mailbox_exists?(mailbox)
          raise NoResponseError.new( UntaggedResponse.new("NO", ResponseText.new( nil, "COPY failed because destination is missing" ), nil ) )
        end
      end

      copy_internal("UID COPY", set, mailbox)
    end

    def uid_move(set, mailbox)
      send_command("UID MOVE", MessageSet.new(set), mailbox)
    end

    # Redefine envelope so our additions are serialized.
    remove_const(:Envelope)
    Envelope = Struct.new(:date, :subject, :from, :sender, :reply_to,
                          :to, :cc, :bcc, :in_reply_to, :message_id,
                          :analyzed, :invalid)
    class Envelope
      attr_accessor :in_reply_to_me

      def serialize
        fields = { 
          :date => date,
          :message_id => message_id,
          :in_reply_to => in_reply_to,
          :from => Array.wrap( from ).map(&:serialize).join( ', ' ), 
          :sender => Array.wrap( sender ).map(&:serialize).join( ', ' ), 
          :to => Array.wrap( to ).map(&:serialize).join( ', ' ), 
          :cc => Array.wrap( cc ).map(&:serialize).join( ', ' ), 
          :bcc => Array.wrap( bcc ).map(&:serialize).join( ', ' ), 
          :subject => subject }

        [ :date, :from, :sender, :to, :cc, :bcc, :message_id, :in_reply_to, :subject ].map{ |field| "#{field.to_s.split('_').map(&:capitalize).join('-')}: #{fields[field].inspect}" unless fields[field].blank? }.compact.join( "\r\n")
      end

      def valid?
        !invalid
      end
    end

    include ImapMixin
    CONNECTION_TIMEOUT = 60 # seconds
    DEFAULT_TIMEOUT = 90 # seconds
    DEFAULT_MAX_RETRIES = 5
    DEFAULT_RETRY_DELAY = 30.seconds
    
    def timeout
      @timeout || DEFAULT_TIMEOUT
    end
    def timeout=(value)
      @timeout = value
    end

    def max_retries
      @max_retries || DEFAULT_MAX_RETRIES
    end
    def max_retries=(value)
      @max_retries = value
    end

    def retry_delay
      @retry_delay || DEFAULT_RETRY_DELAY
    end
    def retry_delay=(value)
      @retry_delay = value
    end

    def initialize(host, port_or_options = {},
                   usessl = false, certs = nil, verify = false)
      super()
      @host = host
      begin
        options = port_or_options.to_hash
      rescue NoMethodError
        # for backward compatibility
        options = {}
        options[:port] = port_or_options
        if usessl
          options[:ssl] = create_ssl_params(certs, verify)
        end
      end

      Timeout.timeout(options[:setup_timeout] || CONNECTION_TIMEOUT) do
        @port = options[:port] || (options[:ssl] ? SSL_PORT : PORT)
        @tag_prefix = "RUBY"
        @tagno = 0
        @parser = ResponseParser.new
        @sock = open_socket(options)
        if options[:ssl]
          begin
            start_tls_session(options[:ssl])
          rescue Errno::ECONNRESET, OpenSSL::SSL::SSLError => first_exception
            if options[:ssl].is_a?(Hash) && options[:ssl].has_key?(:ssl_version)
              raise
            end
            # SB-8871 Retry with tlsv1
            ssl_version_options = {:ssl_version => :TLSv1}
            ssl_version_options.merge!(options[:ssl]) if options[:ssl].is_a?(Hash)
            reopen_socket(options)
            begin
              start_tls_session(ssl_version_options)
            rescue Errno::ECONNRESET, OpenSSL::SSL::SSLError
              # SB-5757 Retry with sslv3
              ssl_version_options[:ssl_version] = :SSLv3_client
              reopen_socket(options)
              begin
                start_tls_session(ssl_version_options)
              rescue OpenSSL::SSL::SSLError
                # NOTE: the exception thrown here is from the first start_tls_session call above
                raise first_exception
              end
            end
          end
          @usessl = true
        else
          @usessl = false
        end
        @responses = Hash.new([].freeze)
        @tagged_responses = {}
        @response_handlers = []
        @tagged_response_arrival = new_cond
        @continuation_request_arrival = new_cond
        @idle_done_cond = nil
        @logout_command_tag = nil
        @debug_output_bol = true
        @exception = nil

        @greeting = get_response
        if @greeting.nil?
          @sock.close
          raise Error, "connection closed"
        end
        if @greeting.name == "BYE"
          @sock.close
          raise ByeResponseError, @greeting
        end

        @client_thread = Thread.current
        @receiver_thread = Thread.start {
          begin
            receive_responses
          rescue Exception
          end
        }
        @receiver_thread_terminating = false
      end
    end

    # NOTE: upstream Net::Imap uses Socket.tcp, which tries every IP address
    # serially and attempts to time out each address individually.
    def open_socket(options)
      addr_infos = Addrinfo.getaddrinfo(@host, @port, Socket::PF_INET, :STREAM)

      addr_info = addr_infos.sample
      if addr_info.nil?
        raise SocketError.new("no public ip addreses found for:#{@host}")
      end
      @sock = TCPSocket.open(addr_info.ip_address, addr_info.ip_port, options[:bind_ip])
    end

    def reopen_socket(options)
      @sock.close
      @sock = open_socket(options)
    end

    def disconnect_with_timeout
      Timeout.timeout(CONNECTION_TIMEOUT) do
        disconnect_without_timeout
      end
    end
    alias_method_chain :disconnect, :timeout

    def get_tagged_response(*args)
      begin
        get_tagged_response_with_timeout(*args)
      rescue Net::IMAP::ResponseParseError => parse_error
        # The stack trace for a parse error just shows the receiving thread
        # which isn't very helpful in finding the source of the commands.
        # Rethrowing the exception here gives the main thread stack trace.
        raise Net::IMAP::ResponseParseError, parse_error.message
      end
    end

    # Workaround yahoo mail bug where they return an untagged response:
    #  NO [UNAVAILABLE] LOGIN failure. Server error--please try again after some time.
    def login(user, password)
      sending_thread = Thread.current
      send_command("LOGIN", user, password) do |resp|
        if resp.is_a?(UntaggedResponse) && resp.name == "NO"
          # Rewind the tag number to regenerate the expected tag
          @tagno -= 1
          tag = generate_tag
          @tagged_responses[tag] = TaggedResponse.new(tag, resp.name, resp.data, resp.raw_data)
          @tagged_response_arrival.broadcast
        end
      end
    end

    # Implementing for MagicMail
    # https://datatracker.ietf.org/doc/draft-yu-imap-client-id/
    def client_id( client_id_type, client_id_token )
      send_command("CLIENTID", client_id_type, client_id_token)
    end

    def send_command_with_retry(cmd, *args, &block)
      retries = 0
      begin
        send_command_without_retry(cmd, *args, &block)
      rescue EOFError
        raise ClosedConnectionError.new
      rescue IOError => ioerror # Allow mailbox watcher to handle a closed connection like a timeout
        if ioerror.message =~ /closed stream/
          raise ClosedConnectionError.new
        else
          raise
        end
      rescue Net::IMAP::ResponseError => e
        if e.message =~ /Mailbox in use|LOGIN.*some.time/i && (e.message !~ ImapConstants::HOTMAIL_RETRY_IGNORE_REGEX) && (retries < max_retries)
          retries += 1
          Rails.logger.info "caught retryable error: #{e}/#{e.class}. retrying #{retries}/#{max_retries}."
          sleep(retry_delay.to_i)
          retry
        else
          raise
        end
      end
    end
    alias_method_chain :send_command, :retry


    def record_response_with_flag_set(*args)
      record_response_without_flag_set(*args)
      @received_a_response = true
    end
    alias_method_chain :record_response, :flag_set

    def get_tagged_response_with_timeout(tag, cmd)
      until @tagged_responses.key?(tag)
        raise @exception if @exception
        @received_a_response = false
        deadline = Time.now + timeout

        @tagged_response_arrival.wait(timeout)
        # Allow more time if some data was received
        if @received_a_response || @got_data
          @received_a_response = false
          @got_data = false
          deadline = Time.now + timeout
        elsif deadline <= Time.now
          raise Timeout::Error.new
        end
      end
      resp = @tagged_responses.delete(tag)
      case resp.name
      when /\A(?:NO)\z/ni
        raise NoResponseError, resp
      when /\A(?:BAD)\z/ni
        raise BadResponseError, resp
      else
        return resp
      end
    end

    alias_method_chain :select, :uid_validity_checks

    # Some imap servers return search results as multiple untagged SEARCH responses.
    def search_internal(cmd, keys, charset)
      if keys.instance_of?(String)
        keys = [RawData.new(keys)]
      else
        normalize_searching_criteria(keys)
      end
      synchronize do
        if charset
          send_command(cmd, "CHARSET", charset, *keys)
        else
          send_command(cmd, *keys)
        end
        return flatten_search_responses(@responses.delete("SEARCH"))
      end
    end

    def unraised_exception
      @exception
    end

    # Default certificate verification off
    def starttls_with_verify(options = {}, verify = false)
      starttls_without_verify(options, verify)
    end
    alias_method_chain :starttls, :verify

    # https://docs.omniref.com/ruby/2.2.0/symbols/Net::IMAP::Error#line=1448
    def start_tls_session(params = {})
      unless defined?(OpenSSL::SSL)
        raise "SSL extension not installed"
      end
      if @sock.kind_of?(OpenSSL::SSL::SSLSocket)
        raise RuntimeError, "already using SSL"
      end
      begin
        params = params.to_hash
      rescue NoMethodError
        params = {}
      end

      # Set the default to VERIFY_NONE.
      # This is the only difference between the official implementation and ours.
      unless params.has_key?(:verify_mode)
        params[:verify_mode] = VERIFY_NONE
      end

      context = SSLContext.new
      context.set_params(params)
      if defined?(VerifyCallbackProc)
        context.verify_callback = VerifyCallbackProc
      end
      @sock = SSLSocket.new(@sock, context)
      @sock.sync_close = true
      @sock.connect
      if context.verify_mode != VERIFY_NONE
        @sock.post_connection_check(@host)
      end
    end

    def compress(scheme)
      synchronize do
        send_command("COMPRESS", scheme)
        @use_deflate = true
        switch_to_deflate
      end
    end

    class ResponseParser
      ADDRESS_CACHE_SIZE = 10000
      ADDRESS_LIST_CACHE_SIZE = 100

      # Object used as a key for lookups in address_lru_cache.
      # Helps avoid having to create a new key object every time a lookup is
      # performed.
      @address_lookup = Address.new() 
      @@address_lru_cache = {}

      # Caches reusable attr key instances
      @@token_name_cache = {}
      @@address_list_cache = {}

      # Caches reusable flag string instances
      @@flag_cache = {}

      remove_const(:DATA_REGEXP)
      remove_const(:BEG_REGEXP)

      # Currently nothing actually uses the value of a space token
      # so save memory by reusing the same object
      SPACE_TOKEN = Token.new(T_SPACE, ' '.freeze).freeze
      NIL_TOKEN = Token.new(T_NIL, 'unused'.freeze).freeze
      LPAR_TOKEN = Token.new(T_LPAR, '('.freeze).freeze
      RPAR_TOKEN = Token.new(T_RPAR, ')'.freeze).freeze
      BSLASH_TOKEN = Token.new(T_BSLASH, '\\'.freeze).freeze
      STAR_TOKEN = Token.new(T_STAR, '*'.freeze).freeze
      LBRA_TOKEN = Token.new(T_LBRA, '['.freeze).freeze
      RBRA_TOKEN = Token.new(T_RBRA, ']'.freeze).freeze
      PLUS_TOKEN = Token.new(T_PLUS, '+'.freeze).freeze
      PERCENT_TOKEN = Token.new(T_PERCENT, '%'.freeze).freeze
      CRLF_TOKEN = Token.new(T_CRLF, '\r\n'.freeze).freeze
      EOF_TOKEN = Token.new(T_EOF, ''.freeze).freeze

      # Remove \r and \n from the excluded characters for QUOTED string to accept
      # incorrect gmail responses, #1872.
      # The invalid \r's and \n's are removed by next_token.
      DATA_REGEXP = /\G(?:\
(?# 1:  SPACE   )( )|\
(?# 2:  NIL     )(NIL)|\
(?# 3:  NUMBER  )(\d+)|\
(?# 4:  QUOTED  )"((?:[^\x00"\\]|\\["\\])*)"|\
(?# 5:  LITERAL )\{(\d+)\}\r\n|\
(?# 6:  LPAR    )(\()|\
(?# 7:  RPAR    )(\)))/ni

      #3461: iCloud imap servers are including \r\r\n line terminations on their CAPABILITIES line (at least). 
      BEG_REGEXP = /\G(?:\
(?# 1:  SPACE   )( +)|\
(?# 2:  NIL     )(NIL)(?=[\x80-\xff(){ \x00-\x1f\x7f%*"\\\[\]+])|\
(?# 3:  NUMBER  )(\d+)(?=[\x80-\xff(){ \x00-\x1f\x7f%*"\\\[\]+])|\
(?# 4:  ATOM    )([^\x80-\xff(){ \x00-\x1f\x7f%*"\\\[\]+]+)|\
(?# 5:  QUOTED - \a-zA-Z* are not valid escapes, the extra characters are
 included to workaround SB-6998 and SB-7200
                )"((?:[^\x00"\\]|\\["\\a-zA-Z\*])*)"|\
(?# 6:  LPAR    )(\()|\
(?# 7:  RPAR    )(\))|\
(?# 8:  BSLASH  )(\\)|\
(?# 9:  STAR    )(\*)|\
(?# 10: LBRA    )(\[)|\
(?# 11: RBRA    )(\])|\
(?# 12: LITERAL )\{(\d+)\}\r\n|\
(?# 13: PLUS    )(\+)|\
(?# 14: PERCENT )(%)|\
(?# 15: CRLF    )(?:\r?)(\r\n)|\
(?# 16: EOF     )(\z))/ni

      # Remove invalid \n's found in quoted strings
      def next_token_with_newline_stripping
        case @lex_state
        when EXPR_BEG
          if @str.index(BEG_REGEXP, @pos)
            @pos = $~.end(0)
            if defined? $1
              return SPACE_TOKEN
            elsif defined? $2
              return NIL_TOKEN
            elsif defined? $3
              return Token.new(T_NUMBER, $+)
            elsif defined? $4
              return Token.new(T_ATOM, $+)
            elsif defined? $5
              tmp = $+.gsub(/\\(["\\])/n, "\\1")
              tmp.gsub!(/[\r\n]/, "")
              return Token.new(T_QUOTED, tmp)
            elsif defined? $6
              return LPAR_TOKEN
            elsif defined? $7
              return RPAR_TOKEN
            elsif defined? $8
              return BSLASH_TOKEN
            elsif defined? $9
              return STAR_TOKEN
            elsif defined? $10
              return LBRA_TOKEN
            elsif defined? $11
              return RBRA_TOKEN
            elsif defined? $12
              len = $+.to_i
              val = @str[@pos, len]
              @pos += len
              return Token.new(T_LITERAL, val)
            elsif defined? $13
              return PLUS_TOKEN
            elsif defined? $14
              return PERCENT_TOKEN
            elsif defined? $15
              return CRLF_TOKEN
            elsif defined? $16
              return EOF_TOKEN
            else
              parse_error("[Net::IMAP BUG] BEG_REGEXP is invalid")
            end
          else
            @str.index(/\S*/n, @pos)
            parse_error("unknown token - %s", $&.dump)
          end
        when EXPR_DATA
          if @str.index(DATA_REGEXP, @pos)
            @pos = $~.end(0)
            if defined? $1
              return SPACE_TOKEN
            elsif defined? $2
              return NIL_TOKEN
            elsif defined? $3
              return Token.new(T_NUMBER, $+)
            elsif defined? $4
              tmp = $+.gsub(/\\(["\\])/n, "\\1")
              tmp.gsub!(/[\r\n]/, "")
              return Token.new(T_QUOTED, tmp)
            elsif defined? $5
              len = $+.to_i
              val = @str[@pos, len]
              @pos += len
              return Token.new(T_LITERAL, val)
            elsif defined? $6
              return LPAR_TOKEN
            elsif defined? $7
              return RPAR_TOKEN
            else
              parse_error("[Net::IMAP BUG] DATA_REGEXP is invalid")
            end
          else
            @str.index(/\S*/n, @pos)
            parse_error("unknown token - %s", $&.dump)
          end
        when EXPR_TEXT
          if @str.index(TEXT_REGEXP, @pos)
            @pos = $~.end(0)
            if $1
              return Token.new(T_TEXT, $+)
            else
              parse_error("[Net::IMAP BUG] TEXT_REGEXP is invalid")
            end
          else
            @str.index(/\S*/n, @pos)
            parse_error("unknown token - %s", $&.dump)
          end
        when EXPR_RTEXT
          if @str.index(RTEXT_REGEXP, @pos)
            @pos = $~.end(0)
            if $1
              return Token.new(T_LBRA, $+)
            elsif $2
              return Token.new(T_TEXT, $+)
            else
              parse_error("[Net::IMAP BUG] RTEXT_REGEXP is invalid")
            end
          else
            @str.index(/\S*/n, @pos)
            parse_error("unknown token - %s", $&.dump)
          end
        when EXPR_CTEXT
          if @str.index(CTEXT_REGEXP, @pos)
            @pos = $~.end(0)
            if $1
              return Token.new(T_TEXT, $+)
            else
              parse_error("[Net::IMAP BUG] CTEXT_REGEXP is invalid")
            end
          else
            @str.index(/\S*/n, @pos) #/
            parse_error("unknown token - %s", $&.dump)
          end
        else
          parse_error("illegal @lex_state - %s", @lex_state.inspect)
        end
      end
      alias_method_chain :next_token, :newline_stripping

      def lookahead
        @token ||= next_token
      end

      # Redefined to work with search_response modifications
      def response
        token = lookahead
        case token.symbol
        when T_CRLF
          # Workaround empty response lines from yahoo's servers #3031
          return UntaggedResponse.new("NO", ResponseText.new( nil, 'Workaround for an empty response line' ), "Workaround for an empty response line")
        when T_PLUS
          result = continue_req
        when T_STAR
          result = response_untagged
          # Return immediately with the modified search responses
          case result.name
          when "SEARCH", "SORT"
            return result
          end
        else
          result = response_tagged
        end
        match(T_CRLF)
        match(T_EOF)
        return result
      end

      # Faster version of search_response parser
      def search_response
        token = match(T_ATOM)
        name = token.value.upcase
        token = lookahead
        data = []
        # Faster parsing of the search response uid list
        @str.scan(/\d+/) {|match| data << match.to_i}
        @pos = @str.index(/\r\n/)
        @pos = @str.length - 1 if @pos.nil?
        return UntaggedResponse.new(name, data, @str)
      end

      def noop_response
        token = match(T_ATOM)
        name = token.value.upcase
        token = lookahead
        return UntaggedResponse.new(name, [], @str)
      end

      def address
        match(T_LPAR)
        if @str.index(ADDRESS_REGEXP, @pos)
          # address does not include literal.
          @pos = $~.end(0)
          name = $1
          route = $2
          mailbox = $3
          host = $4
          for s in [name, route, mailbox, host]
            if s
              s.gsub!(/\\(["\\])/n, "\\1")
            end
          end
        else
          name = nstring
          match(T_SPACE)
          route = nstring
          match(T_SPACE)
          mailbox = nstring
          match(T_SPACE)
          host = nstring
          token = lookahead
          # #3175 Ignore unexpected space before the closing )
          if token.symbol == T_SPACE
            match(T_SPACE)
          end
          match(T_RPAR)
        end
        return self.class.build_address(name, route, mailbox, host)
      end

      # Avoids creating identical address objects as much as possible by reusing
      # instances.
      def self.build_address(name, route, mailbox, host)
        lookup_object = @address_lookup
        lookup_object.name = name
        lookup_object.route = route
        lookup_object.mailbox = mailbox
        lookup_object.host = host
        @@address_lru_cache.fetch(lookup_object) do |lookup_object|
           # It's easier to clear the cache than to implement a real lru cache.
           @@address_lru_cache.clear if @@address_lru_cache.size > ADDRESS_CACHE_SIZE
           cloned_object = lookup_object.clone
           saved = @@address_lru_cache[cloned_object] = cloned_object
           saved
        end
      end

      # Modified to reuse the same string instances as attr keys to save memory
      def msg_att(n)
        match(T_LPAR)
        attr = {}
        while true
          token = lookahead
          case token.symbol
          when T_RPAR
            shift_token
            break
          when T_SPACE
            shift_token
            token = lookahead
          end
          case token.value
          when /\A(?:ENVELOPE)\z/ni
            name, val = envelope_data
          when /\A(?:FLAGS)\z/ni
            name, val = flags_data
          when /\A(?:INTERNALDATE)\z/ni
            name, val = internaldate_data
          when /\A(?:RFC822(?:\.HEADER|\.TEXT)?)\z/ni
            name, val = rfc822_text
          when /\A(?:RFC822\.SIZE)\z/ni
            name, val = rfc822_size
          when /\A(?:BODY(?:STRUCTURE)?)\z/ni
            name, val = body_data
          when /\A(?:UID)\z/ni
            name, val = uid_data
          when /\A(?:X-GM-LABELS)\z/ni
            name, val = labels_data
          else
            parse_error("unknown attribute `%s' for {%d}", token.value, n)
          end
          # VC change begin
          reused_name = @@token_name_cache.fetch(name) do |name|
            frozen_name = name.dup.force_encoding( Encoding::ASCII_8BIT ).freeze
            @@token_name_cache[frozen_name] = frozen_name
          end 
          attr[reused_name] = val
          #VC change end
        end
        return attr
      end

      def nstring_with_niling_blanks
        string_value = nstring_without_niling_blanks
        if !string_value.nil? && string_value.blank?
          nil
        else
          string_value
        end
      end

      alias_method_chain :nstring, :niling_blanks

      def labels_data
        token = match(T_ATOM)
        name = token.value.upcase
        match(T_SPACE)
        labels_list = []
        match(T_LPAR)
        while true
          token = lookahead
          case token.symbol
          when T_RPAR
            shift_token
            break
          when T_SPACE
            shift_token
          else
            labels_list << astring
          end
        end
        return name, labels_list
      end

      # Modified to reuse atom string instance
      def flag_list
        if @str.index(/\(([^)]*)\)/ni, @pos)
          @pos = $~.end(0)
          return $1.scan(FLAG_REGEXP).collect { |flag, atom|
            # VC change begin
            if atom
              atom.freeze
              @@flag_cache[atom] ||= atom 
            else
              flag.capitalize.intern
            end
            # VC change end
          }
        else
          parse_error("invalid flag list")
        end
      end

      def response_untagged
        match(T_STAR)
        match(T_SPACE)
        token = lookahead
        if token.symbol == T_NUMBER
          return numeric_response
        elsif token.symbol == T_ATOM
          case token.value
          when /\A(?:OK|NO|BAD|BYE|PREAUTH)\z/ni
            return response_cond
          when /\A(?:FLAGS)\z/ni
            return flags_response
          when /\A(?:LIST|XLIST|LSUB)\z/ni
            return list_response
          when /\A(?:QUOTA)\z/ni
            return getquota_response
          when /\A(?:QUOTAROOT)\z/ni
            return getquotaroot_response
          when /\A(?:ACL)\z/ni
            return getacl_response
          when /\A(?:SEARCH|SORT)\z/ni
            return search_response
          when /\A(?:THREAD)\z/ni
            return thread_response
          when /\A(?:STATUS)\z/ni
            saved_status_response = status_response
            # Workaround issue where exchange returns extras spaces after STATUS
            # responses, http://rubyforge.org/tracker/index.php?func=detail&aid=28031&group_id=426&atid=1698
            if lookahead.symbol == T_SPACE
              shift_token
            end
            return saved_status_response
          when /\A(?:CAPABILITY)\z/ni
            # SB-6745 Workaround garbage in capability response
            @str.gsub!(/\xFF/n, "")
            return capability_response
          #2307: AOL returns NOOP in response to an apparent long-running UID COPY command
          when /\A(?:NOOP)\z/ni
            return noop_response
          else
            return text_response
          end
        else
          parse_error("unexpected token %s", token.symbol)
        end
      end

      def address_list_with_cache
        address_array = address_list_without_cache
        @@address_list_cache.fetch(address_array) do |address_array|
          @@address_list_cache.clear if @@address_list_cache.size > ADDRESS_LIST_CACHE_SIZE
          address_array.freeze
          @@address_list_cache[address_array] = address_array
          address_array
        end
      end
      alias_method_chain :address_list, :cache

      FLAGS_CLOSEOUT = "] .\r\n"

      # Using the ruby 1.9 version of this method which fixes the bugs in the
      # 1.8 parser
      def resp_text_code
        @lex_state = EXPR_BEG
        match(T_LBRA)
        token = match(T_ATOM)
        name = token.value.upcase
        case name
        when /\A(?:ALERT|PARSE|READ-ONLY|READ-WRITE|TRYCREATE|NOMODSEQ)\z/n
          result = ResponseCode.new(name, nil)
        when /\A(?:PERMANENTFLAGS)\z/n
          match(T_SPACE)
          result = ResponseCode.new(name, flag_list)
          # SB-5706 Workaround invalid PERMANENTFLAGS response
          if lookahead.symbol != T_RBRA
            shift_token
            @pos = 0
            @str = FLAGS_CLOSEOUT
          end
        when /\A(?:UIDVALIDITY|UIDNEXT)\z/n
          match(T_SPACE)
          result = ResponseCode.new(name, number)
        when /\AUNSEEN\z/n
          match(T_SPACE)
          # Allow negative numbers here. We don't use unseen.
          factor = if @str[@pos] == '-'
                     # skip over the -
                     @pos = @pos + 1
                     -1
                   else
                     1
                   end
          result = ResponseCode.new(name, factor * number)
        else
          token = lookahead
          if token.symbol == T_SPACE
            shift_token
            @lex_state = EXPR_CTEXT
            token = match(T_TEXT)
            @lex_state = EXPR_BEG
            result = ResponseCode.new(name, token.value)
          else
            result = ResponseCode.new(name, nil)
          end
        end
        match(T_RBRA)
        @lex_state = EXPR_RTEXT
        return result
      end

      def parse_namespace_response(r)
        @str = r
        @pos = 0
        namespaces = r.scan(/(\(\(.+?\)\)|NIL)/).map do |part|
          part.first
        end.map do |part|
          if part == "NIL"
            nil
          else
            part.scan(/\([^(]+?\)/).map do |subpart|
              subpart.match(/"(.*?)"\s+("(.*?)"|NIL)/) or parse_error("bad namespace pair `%s'", subpart)
              Namespace.new($1, $3 == "NIL" ? nil : $3)
            end
          end
        end
        namespaces.size == 3 or parse_error("bad namespaces response '%s'", r)
        {:personal => namespaces[0], :other_users => namespaces[1], :shared => namespaces[2]}
      end

      def parse_error(fmt, *args)
        msg = format(fmt, *args) + ", @pos:#{@pos} @str:#{@str.dump}"
        raise ResponseParseError, msg
      end

      DoubleQuote = "\"".force_encoding( Encoding::ASCII_8BIT ).freeze

      # Override to fix #3674
      def mailbox_list
        attr = flag_list
        match(T_SPACE)
        token = match(T_QUOTED, T_NIL)
        if token.symbol == T_NIL
          delim = nil
        else
          delim = token.value
        end
        match(T_SPACE)

        # Get the unparsed mailbox name to make fixups 
        parsed_text = @str.slice(0, @pos)
        unparsed_text = @str.slice(@pos, @str.length - @pos)

        unless unparsed_text.empty?
          #3741 Add missing quotes around mailbox names
          unless unparsed_text.include?(DoubleQuote)
            unparsed_text.gsub!(/\A(.*)\r\n\z/, "#{DoubleQuote}\\1#{DoubleQuote}\r\n")
          end
          #4477 Remove \ before parentheses
          unparsed_text.gsub!(/(?<!\\)\\(\(|\))/, "\\1") 

          # At least one server fails to escape "'s in mailbox names #3674.  To
          # deal with this escape any unescaped "'s assuming the quote preceding
          # the CRLF is the delimiter.
          unparsed_text =  unparsed_text.gsub(/^([^"]*")(.*)("\r\n)$/) do |match_text|
            prefix = $1
            trailer = $3
            # Ruby 1.8.7's regexes do not support negative lookbehind, so reverse
            # the string and use negative lookahead.
            escaped_content = $2.reverse.gsub(/"(?!\\)/, "\"\\").reverse
            "#{prefix}#{escaped_content}#{trailer}"
          end
          @str = parsed_text + unparsed_text
        end
        # SB-5633 Remove newline after folder name that next_token fails on
        @str.sub!(/\n\r\n\z/, "\r\n")
        
        name = astring
        # SB-5511 skip trailing space after mailbox name
        MailboxList.new(attr, delim, name).tap do |mailbox_list|
          # SB-6224 Workaround literal string with short count 
          if mailbox_list.name.last == "\r"
            mailbox_list.name = mailbox_list.name.chomp
            @pos = @pos - 1
          end
          # SB-5633 Skip problem newline
          if lookahead.symbol == T_SPACE
            match(T_SPACE)
          end
        end
      end

      # SB-5706 Workaround flags responses containing incorrect parentheses
      def flags_response
        token = match(T_ATOM)
        name = token.value.upcase
        match(T_SPACE)
        UntaggedResponse.new(name, flag_list, @str).tap do |response|
          # Check for unconsumed input and skip it, this will discard
          # the remaining flags.
          end_marker_position = @str.index(/\r\n/ni, @pos)
          if end_marker_position > @pos
            @pos = end_marker_position
          end
        end
      end

      def format_string_with_force_encoding( data )
        encoding = data.encoding
        begin
          data = data.force_encoding( Encoding::ASCII_8BIT ) unless data.frozen?
          format_string_without_force_encoding( data )
        ensure
          data.force_encoding( encoding ) unless data.frozen?
        end
      end
      alias_method_chain :format_string, :force_encoding
    end

    class Address

      def blank?
        mailbox.blank? && host.blank?
      end

      def self.from_string(s)
        Address.new.tap do |addr|
          parts = s.parse_email_address
          addr.name = parts[:name]
          addr.host = parts[:host]
          addr.mailbox = parts[:mailbox]
        end
      end

      def serialize(opts={})
        include_name = !name.blank? && opts.fetch(:include_name, true)

        # host can be nil, but not mailbox.
        # this is consistent with Mail::Address.new().
        if mailbox.nil?
          nil
        else
          if host.blank?
            if include_name
              "#{name.from_q_encoding} <#{mailbox.force_valid_utf8}>"
            else
              mailbox
            end
          else
            if include_name
              "#{name.from_q_encoding} <#{mailbox.force_valid_utf8}@#{host.force_valid_utf8}>"
            else
              "#{mailbox.force_valid_utf8}@#{host.force_valid_utf8}"
            end
          end
        end
      end
    end

    def put_string(str)
      str = str.force_encoding( Encoding::ASCII_8BIT ) unless str.frozen?
      @put_string_buffer ||= "".force_encoding( Encoding::ASCII_8BIT )
      @put_string_buffer.concat( str )
      if @put_string_buffer.end_with?( CRLF )
        @sock.print(@put_string_buffer)

        if @@debug
          $stderr.print("C: ")
          $stderr.print(@put_string_buffer.gsub(/\n(?!\z)/n, "\nC: "))
        end

        @put_string_buffer = nil
      end
    end

    def send_string_data_with_force_encoding( *args )
      data = args.first
      encoding = data.encoding
      begin
        data = data.force_encoding( Encoding::ASCII_8BIT ) unless data.frozen?
        send_string_data_without_force_encoding( *args )
      ensure
        data.force_encoding( encoding ) unless data.frozen?
      end
    end
    alias_method_chain :send_string_data, :force_encoding

    def send_quoted_string_with_force_encoding( data )
      encoding = data.encoding
      begin
        data = data.force_encoding( Encoding::ASCII_8BIT ) unless data.frozen?
        send_quoted_string_without_force_encoding( data )
      ensure
        data.force_encoding( encoding ) unless data.frozen?
      end
    end
    alias_method_chain :send_quoted_string, :force_encoding

    def put_string_with_rails_logging(str)
      put_string_without_rails_logging(str)

      return if Rails.logger.level != 0

      if @debug_output_buf.nil?
        @debug_output_buf = "C: "
      end
      @debug_output_buf += str.gsub(/\n(?!\z)/n, "\nC: ")
      if /\r\n\z/n.match(str)
        @debug_output_buf.sub!(/(C: RUBY\d+ LOGIN )(?:.*\r)/n, '\1')
        @debug_output_buf.sub!(/(C: \S+)(?:\r)/n, 'BLOB')
        Rails.logger.debug { @debug_output_buf }
        @debug_output_buf = nil
      end
    end
    alias_method_chain :put_string, :rails_logging

    # log to Rails.logger instead of $stderr
    def get_response
      get_response_without_rails_logging.tap do |resp|
        unless resp.try(:raw_data).nil?
          Rails.logger.debug { resp.raw_data[0, 4096].gsub(/^/n, "S: ") }
        end
      end
    end

    # Remove any fetch responses from previous before performing a new
    # search. This is to get rid of FETCH responses pushed by davmail.
    def uid_search_with_clear_fetch(*args)
      responses.delete('FETCH')
      uid_search_without_clear_fetch(*args)
    end
    alias_method_chain :uid_search, :clear_fetch

    def uid_expunge( set )
      synchronize do
        send_command( "UID EXPUNGE", MessageSet.new( set ) )
        return @responses.delete( "UID EXPUNGE" )
      end
    end

    def use_fetch_for_uid_search?
      if @use_fetch_for_uid_search.nil?
        @use_fetch_for_uid_search = (greeting.data.text =~ /InterMail/i) || false
      end
      @use_fetch_for_uid_search
    end

    def use_fetch_for_uid_search=(value)
      @use_fetch_for_uid_search = value
    end

    def use_fetch_for_search_all=(value)
      @use_fetch_for_search_all = value
    end

    # SB-9266 Workaround for UID SEARCH ALL failing with a BYE response. Does not always work.
    def use_fetch_for_search_all?
      if @use_fetch_for_search_all.nil?
        # The greeting currently looks like " IMAP4rev1 imapgate-1.8.1_01.20166"
        # => "earthlink.net IMAP Service 6527 imapd EL_0_1_42_P at oim-genesis.atl.sa.earthlink.net ready"
        @use_fetch_for_search_all = (greeting.data.text =~ /earthlink\.net IMAP Service|imapgate|Mail2World/i) || false
      end
      @use_fetch_for_search_all
    end

    class WrapperResponse < Struct.new(:text)
      def data
        self
      end
    end

    def self.make_error_response(error_class, message)
      error_class.new(WrapperResponse.new(message))
    end

    def self.make_no_response(message)
      make_error_response(Net::IMAP::NoResponseError, message)
    end

    def self.make_bad_response(message)
      make_error_response(Net::IMAP::BadResponseError, message)
    end

    class MessageSet
      def validate_internal_with_large_int(data)
        case data
        when Integer
          my_ensure_nz_number(data)
        else
          validate_internal_without_large_int(data)
        end
      end
      alias_method_chain :validate_internal, :large_int
      
      def my_ensure_nz_number(num)
        if num < -1 || num == 0
          msg = "nz_number must be non-zero unsigned integer: " +
            num.inspect
          raise DataFormatError, msg
        end
      end
    end
  end
end
