class DeflateSocket
  def initialize(socket, current_buffer)
    @socket = socket
    @inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    @inflater << current_buffer if current_buffer.present?

    @deflater = Zlib::Deflate.new(nil, -Zlib::MAX_WBITS)
    @read_buffer = ""
    finalizer_proc = proc do
      begin
        @inflater.end
        @deflater.close
      rescue
      end
    end
    ObjectSpace.define_finalizer(self, finalizer_proc)
  end

  def add_input(buffer)
    @inflater << buffer
    @read_buffer << @inflater.flush_next_out
  end

  def read(count)
    check_eof
    while !@inflater.finished? && @read_buffer.size < count do
      read_from_socket
      break if @socket_end_of_file
    end
    @read_buffer.slice!(0, count)
  end

  def readpartial(count)
    check_eof
    while !@inflater.finished? && @read_buffer.size == 0
      read_from_socket
    end
    @read_buffer.slice!(0, count)
  end

  def close
    @socket.close
    close_streams
  end

  # Support this SSLSocket method so we don't have to reimplement Net::IMAP disconnect
  def io
    @socket.io
  end

  def shutdown
    @socket.shutdown
    close_streams
  end

  def print(data)
    @socket.write(@deflater.deflate(data, Zlib::SYNC_FLUSH))
  end

  def closed?
    @socket.closed?
  end

  private
  def close_streams
    @inflater.reset
    @deflater.reset
  end

  def read_from_socket
    unless @socket_end_of_file
      begin
        raw_read = @socket.readpartial(1000)
        @inflater << raw_read 
        @read_buffer << @inflater.flush_next_out
      rescue EOFError => eof
        @socket_end_of_file = true
        begin
          @read_buffer << @inflater.finish
        rescue Zlib::BufError
          raise eof
        end
      end
    end
  end

  def check_eof
    if @inflater.finished? && @read_buffer.size == 0
      raise EOFError
    end
  end

end
