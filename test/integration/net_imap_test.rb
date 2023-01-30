require_relative "../test_helper"
require 'imap_constants'

class MockResponsesIMAP < Net::IMAP
  def mock_response
    nil
  end

  def get_response
    while true
      Thread.pass
      r = mock_response
      return r unless r.nil?
    end
  end
end

class UidValidityTester
  include ImapMixin

  public
  def set_responses(response)
    @responses = response
  end

  def select_without_uid_validity_checks(mailbox)
  end

end

class NetImapTest < ActiveSupport::TestCase

  test "login handles untagged unavailable response" do
    parser = Net::IMAP::ResponseParser.new

    Net::IMAP.any_instance.stubs(:open_socket)
    greeting = Net::IMAP::UntaggedResponse.new
    untagged_response = parser.parse("* NO [UNAVAILABLE] LOGIN failure. Server error--please try again after some time. Error code OCF12\r\n")
    ok_response = parser.parse("RUBY0003 OK AUTHENTICATE completed\r\n")

    MockResponsesIMAP.any_instance.stubs(:mock_response).returns(greeting)
    imap = MockResponsesIMAP.new('test.host')
    imap.retry_delay = 0.01
    imap.stubs(:put_string)
    # Skip the starttls code
    imap.instance_variable_set(:@usessl, true)

    # without retry
    imap.max_retries = 0
    MockResponsesIMAP.any_instance.stubs(:mock_response).returns(untagged_response).then.returns(nil)
    assert_raise Net::IMAP::NoResponseError do
      imap.login('username', 'secret')
    end

    # with retry
    imap.max_retries = 1
    MockResponsesIMAP.any_instance.stubs(:mock_response).returns(untagged_response).then.returns(ok_response).then.returns(nil)
    assert_nothing_raised do
      imap.login('username', 'secret')
    end
  end

  test "send_command_with_retry" do
    bad = Net::IMAP.make_bad_response('UID FETCH Mailbox in use. Please try again later')
    no = Net::IMAP.make_bad_response('UID FETCH Mailbox in use. Please try again later')
    fetch_result = Net::IMAP::FetchData.new(1, {"UID" => 1})

    Net::IMAP.any_instance.stubs(:open_socket)
    Net::IMAP.any_instance.stubs(:get_response).returns(Net::IMAP::UntaggedResponse.new)
    imap = Net::IMAP.new('test.host')
    imap.max_retries = 3
    imap.retry_delay = 0
    responses = mock("responses")
    responses.stubs(:delete).with("FETCH").returns([fetch_result])
    imap.instance_variable_set(:@responses, responses)

    imap.stubs(:send_command_without_retry).raises(bad).then.raises(no).then.raises(bad).then.returns(true)
    assert_equal [fetch_result], imap.uid_fetch([1], ImapConstants::FetchItem::STANDARD_FETCH_LIST)
    
    imap.stubs(:send_command_without_retry).raises(no).then.raises(bad).then.raises(no).then.raises(bad)
    assert_raise Net::IMAP::BadResponseError do
      assert_equal [fetch_result], imap.uid_fetch([1], ImapConstants::FetchItem::STANDARD_FETCH_LIST)
    end
  end

  # SB-7759
  test "send_command_with_retry with hotmail error" do
    no = Net::IMAP.make_bad_response('Error 9. Server error. Please try again later.')

    Net::IMAP.any_instance.stubs(:open_socket)
    Net::IMAP.any_instance.stubs(:get_response).returns(Net::IMAP::UntaggedResponse.new)
    imap = Net::IMAP.new('test.host')

    imap.expects(:send_command_without_retry).raises(no)

    assert_raise Net::IMAP::BadResponseError do
      imap.uid_fetch([1], ImapConstants::FetchItem::STANDARD_FETCH_LIST)
    end
  end

  test "rethrow_parse_error" do
    Net::IMAP.any_instance.stubs(:open_socket)
    Net::IMAP.any_instance.stubs(:get_response).returns(Net::IMAP::UntaggedResponse.new)
    imap = Net::IMAP.new('test.host')
    parse_error = Net::IMAP.make_error_response(Net::IMAP::ResponseParseError, "parse error")
    condition_variable = imap.instance_variable_get(:@tagged_response_arrival)
    condition_variable.expects(:wait).raises(parse_error)
    new_exception = assert_raise Net::IMAP::ResponseParseError do
      imap.synchronize do
        imap.send(:get_tagged_response, "TAG", "FETCH")
      end
    end
    assert_equal parse_error.message, new_exception.message
  end
 
  test "blank address" do
    assert_equal true, Net::IMAP::Address.new.blank?
    assert_equal true, Net::IMAP::Address.from_hash(:mailbox => nil, :host => nil).blank?
    assert_equal false, Net::IMAP::Address.from_hash(:mailbox => "a", :host => nil).blank?
    assert_equal false, Net::IMAP::Address.from_hash(:mailbox => nil, :host => "g.com").blank?
    assert_equal false, Net::IMAP::Address.from_hash(:mailbox => "a", :host => "g.com").blank?
  end

  test "serialize address" do
    assert_equal "Foo Bar <foo@bar.com>", Net::IMAP::Address.new("Foo Bar", nil, "foo", "bar.com").serialize
    assert_equal "foo@bar.com", Net::IMAP::Address.new("Foo Bar", nil, "foo", "bar.com").serialize(:include_name => false)
    assert_equal "foo@bar.com", Net::IMAP::Address.new(nil, nil, "foo", "bar.com").serialize
    assert_equal "foo@bar.com", Net::IMAP::Address.new("", nil, "foo", "bar.com").serialize
    assert_equal "foo", Net::IMAP::Address.new("", nil, "foo", nil).serialize
    assert_nil Net::IMAP::Address.new("", nil, nil, "bar.com").serialize
  end

  test "parser_reuses_flag_atoms" do
    parser = Net::IMAP::ResponseParser.new

    parsed = parser.parse("* 1 FETCH (FLAGS (text \Flagged second \Seen))\r\n")
    text = parsed.data.attr["FLAGS"][0]
    second = parsed.data.attr["FLAGS"][2]

    parser = Net::IMAP::ResponseParser.new
    parsed = parser.parse("* 2 FETCH (FLAGS (\Flagged \Seen text second))\r\n")
    assert_same text, parsed.data.attr["FLAGS"][2]
    assert_same second, parsed.data.attr["FLAGS"][3]
  end

  test "parser_reuses_attr_keys" do
    parser = Net::IMAP::ResponseParser.new

    response = "* 1 FETCH (RFC822.SIZE 2176 FLAGS (NonJunk \Flagged \Seen) ENVELOPE (\"Sun, 7 Mar 2010 22:19:29 -0500\" \"silent treatment\" ((\"Test Subject\" NIL \"test.subject\" \"gmail.com\")) ((\"Test Subject\" NIL \"test.subject\" \"gmail.com\")) ((\"Test Subject\" NIL \"test.subject\" \"gmail.com\")) ((NIL NIL \"jdsubject\" \"gmail.com\")) NIL NIL NIL \"<xxxx@mail.gmail.com>\"))\r\n"
    parsed = parser.parse(response)
    first_keys = parsed.data.attr.keys

    parser = Net::IMAP::ResponseParser.new
    parsed = parser.parse(response)
    second_time_keys = parsed.data.attr.keys
    first_keys.each_with_index do |item, i|
      assert_same second_time_keys[i], item
    end
  end   

  test "parse_noop_response" do
    assert_equal(Net::IMAP::UntaggedResponse.new( "NOOP", [], "* NOOP\r\n" ),
                 Net::IMAP::ResponseParser.new.parse( "* NOOP\r\n" ))
  end

  test "parse_namespace_response" do
    assert_equal({:personal => [Net::IMAP::Namespace.new('INBOX/', '/')],
                   :other_users => nil,
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("INBOX/" "/")) NIL NIL'))

    # yahoo mail
    assert_equal({:personal => [Net::IMAP::Namespace.new("", nil)],
                   :other_users => nil,
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" NIL)) NIL NIL'))

    # Examples copied from RFC2342
    # example 5.1
    assert_equal({:personal => nil,
                   :other_users => nil,
                   :shared => [Net::IMAP::Namespace.new('', '.')]},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('NIL NIL (("" "."))'))

    # example 5.2
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => nil,
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) NIL NIL'))

    # example 5.3
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => nil,
                   :shared => [Net::IMAP::Namespace.new('Public Folders/', '/')]},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) NIL (("Public Folders/" "/"))'))

    # example 5.4
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => [Net::IMAP::Namespace.new('~', '/')],
                   :shared => [Net::IMAP::Namespace.new('#shared/', '/'), Net::IMAP::Namespace.new('#public/', '/'), Net::IMAP::Namespace.new('#ftp/', '/'), Net::IMAP::Namespace.new('#news.', '.')]},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) (("~" "/")) (("#shared/" "/")("#public/" "/")("#ftp/" "/")("#news." "."))'))

    # example 5.5
    assert_equal({:personal => [Net::IMAP::Namespace.new('INBOX.', '.')],
                   :other_users => nil,
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("INBOX." ".")) NIL  NIL'))

    # example 5.6
    # NOT SUPPORTED

    # example 5.7
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => [Net::IMAP::Namespace.new('Other Users/', '/')],
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) (("Other Users/" "/")) NIL'))

    # example 5.8
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => [Net::IMAP::Namespace.new('#Users/', '/')],
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) (("#Users/" "/")) NIL'))

    # example 5.9
    assert_equal({:personal => [Net::IMAP::Namespace.new('', '/')],
                   :other_users => [Net::IMAP::Namespace.new('~', '/')],
                   :shared => nil},
                 Net::IMAP::ResponseParser.new.parse_namespace_response('(("" "/")) (("~" "/")) NIL'))
  end

  test "uid_validity_checks" do
    imap = UidValidityTester.new
    UidValidityTester.set_enable_uid_validity_checks(true)
    imap.set_responses({'UIDVALIDITY' => [1]})
    imap.select_with_uid_validity_checks("german")

    imap.set_responses({'UIDVALIDITY' => [2]})
    imap.select_with_uid_validity_checks("french")

    imap.set_responses({'UIDVALIDITY' => [3]})
    assert_raises Net::IMAP::UidValidityChanged do
      imap.select_with_uid_validity_checks("german")
    end

    imap.set_responses({'UIDVALIDITY' => [2]})
    imap.select_with_uid_validity_checks("french")

    imap.set_responses({'UIDVALIDITY' => [3]})
    imap.select_with_uid_validity_checks("german")

    imap.set_responses({'UIDVALIDITY' => [2]})
    imap.select_with_uid_validity_checks("other")

    # Shouldn't get an exception
    UidValidityTester.clear_uid_validity_values
    imap.set_responses({'UIDVALIDITY' => [4]})
    assert_nothing_raised do
      imap.select_with_uid_validity_checks("german")
    end
  end

  test "receive_responses does not throw bye error after disconnect" do
    begin
      server = TCPServer.new(nil, 0)
      server_port = server.addr[1]
      server_thread = Thread.start do
        Thread.current.abort_on_exception = true
        client = server.accept
        client.print "* OK IMAP4 ready\r\n"
        login_tag = client.readline.split.first
        client.print "#{login_tag} NO Invalid login or password\r\n* BYE IMAP server terminating connection is gone\r\n"
        client.close
      end

      receiver_thread = nil
      assert_raises Net::IMAP::NoResponseError do
        imap = Net::IMAP.new(nil, server_port, false)
        receiver_thread = imap.instance_variable_get(:@receiver_thread)
        imap.login('foo@aol.com', 'bad secret')
      end
      assert_not_nil receiver_thread
      # This ensures the receiver thread is done
      begin
        assert_not_nil receiver_thread.join(5)
      rescue IOError # From the closed connection
      end
    ensure
      server_thread.join(1) if server_thread
    end
  end

  test "retry_select_succeeds" do
    imap = UidValidityTester.new
    try_again_response = Net::IMAP.make_no_response("Mailbox in use. Please try again later")
    imap.stubs(:sleep)
    imap.instance_eval { @responses = { "UIDVALIDITY" => [10] } }
    imap.stubs(:select_without_uid_validity_checks).raises(try_again_response).then.raises(try_again_response).then.returns(true)
    imap.select_with_uid_validity_checks("mailbox")
  end

  test "retry_select_fails" do
    imap = UidValidityTester.new
    try_again_response = Net::IMAP.make_no_response("Mailbox in use. Please try again later")
    imap.stubs(:sleep)
    imap.stubs(:select_without_uid_validity_checks).raises(try_again_response)
    final_exception = assert_raises Net::IMAP::SelectFolderFailed do
      imap.select_with_uid_validity_checks("mailbox")
    end
    assert_equal "Could not select mailbox after #{ImapMixin::SELECT_RETRY_ATTEMPTS} tries last response was:Mailbox in use. Please try again later", final_exception.message
  end

  test "retry_select_fails_on_bad_response" do
    imap = UidValidityTester.new
    error_message = "arbitrary error"
    try_again_response = Net::IMAP.make_bad_response(error_message)
    imap.expects(:sleep).times(Net::IMAP::SELECT_RETRY_ATTEMPTS-1)
    imap.stubs(:select_without_uid_validity_checks).raises(try_again_response)
    final_exception = assert_raises Net::IMAP::BadResponseError do
      imap.select_with_uid_validity_checks("mailbox")
    end
    assert_equal error_message, final_exception.message
  end


  # #3031
  test "parse_empty_lines" do
    empty_response_line = "\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(empty_response_line)
    assert parsed_response.is_a?(Net::IMAP::UntaggedResponse)
    assert parsed_response.raw_data =~ /Workaround/
  end
 
  # #1872 Test workaround for gmail bug where \n appears in quoted strings
  test "parse_quoted_strings_containing_newlines" do
    bad_response = "* 19627 FETCH (UID 50494 ENVELOPE (\"Sxt, 5 Fxx 2011 18:51:24 -0500\" \"Rx: Txx Supxr.... Bowx\" ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Axxxxnxxr Vxsxno\" NIL \"xxxxvxsxno\" \"xxxxx.xox\") (\"Anxrxx Hxxx\" NIL \"xnxrxxrxxxx\" \"xxxxx.xox\")) ((\"Txx Lxxxxttxr\" NIL \"txxxxxxttxr\" \"xxxxx.xox\") (\"Dxxxrxv Dxxxx\" NIL \"xxxx13\" \"xxxxx.xox\") (\"Ryxn Ruxxno\" NIL \"ryxn_ruxxno\" \"yxxoo.xox\") (\"Ursuxx Lxxx\" NIL \"ursuxx.xxxx\" \"xxxxx.xox\") (\"Josxpx Moronx\" NIL \"xxoronx9\" \"xxxxx.xox\") (\"Cxrxs\n Huxx\" NIL \"xxuxx\" \"xntxurxuxsx.xox\") (\"Axxx Hoyt\" NIL \"xxxx.xoyt\" \"tuxts.xxu\") (\"Axxt\n Vxrxxxsx\" NIL \"xxxt.vxrxxxsx\" \"xxxxx.xox\") (\"Mxxxn Sxxx\" NIL \"xxxxn\" \"rxtxrxxxxx.nxt\") (\"Joy\" NIL \"xux58x\" \"xox.xox\")) NIL \"<AANLxTxxxKD=QpO0CxzXBxxx9vxUo2PxS8B2MLZx-sxUr@xxxx.xxxxx.xox>\" \"<840102.54856.qx@sxtp103-xox.xxz.xxxx.xx4.yxxoo.xox>\"))\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(bad_response)
    assert_equal "Cxrxs Huxx", parsed_response.data.attr["ENVELOPE"].cc[5].name

    bad_response = "* 19627 FETCH (UID 50494 ENVELOPE (\"Sxt, 5 Fxx 2011 18:51:24 -0500\" \"Rx: Txx Supxr.... Bowx\" ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Mxtt Bxrx\" NIL \"xxrx1107\" \"yxxoo.xox\")) ((\"Axxxxnxxr Vxsxno\" NIL \"xxxxvxsxno\" \"xxxxx.xox\") (\"Anxrxx Hxxx\" NIL \"xnxrxxrxxxx\" \"xxxxx.xox\")) ((\"Txx Lxxxxttxr\" NIL \"txxxxxxttxr\" \"xxxxx.xox\") (\"Dxxxrxv Dxxxx\" NIL \"xxxx13\" \"xxxxx.xox\") (\"Ryxn Ruxxno\" NIL \"ryxn_ruxxno\" \"yxxoo.xox\") (\"Ursuxx Lxxx\" NIL \"ursuxx.xxxx\" \"xxxxx.xox\") (\"Josxpx Moronx\" NIL \"xxoronx9\" \"xxxxx.xox\") (\"Cxrxs\r Huxx\" NIL \"xxuxx\" \"xntxurxuxsx.xox\") (\"Axxx Hoyt\" NIL \"xxxx.xoyt\" \"tuxts.xxu\") (\"Axxt\n Vxrxxxsx\" NIL \"xxxt.vxrxxxsx\" \"xxxxx.xox\") (\"Mxxxn Sxxx\" NIL \"xxxxn\" \"rxtxrxxxxx.nxt\") (\"Joy\" NIL \"xux58x\" \"xox.xox\")) NIL \"<AANLxTxxxKD=QpO0CxzXBxxx9vxUo2PxS8B2MLZx-sxUr@xxxx.xxxxx.xox>\" \"<840102.54856.qx@sxtp103-xox.xxz.xxxx.xx4.yxxoo.xox>\"))\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(bad_response)
    assert_equal "Cxrxs Huxx", parsed_response.data.attr["ENVELOPE"].cc[5].name

    # SB-5349
    bad_list_response = "* LIST (\\HasNoChildren) \"/\" \"Deleted Items/zz - Incomplete Do Not Use - Projects/Opower\n\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(bad_list_response)
    assert_equal "Deleted Items/zz - Incomplete Do Not Use - Projects/Opower", parsed_response.data.name

    # SB-5633
    bad_list_response = "* LIST (\\HasNoChildren) \"/\" Projects/Opower\n\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(bad_list_response)
    assert_equal "Projects/Opower", parsed_response.data.name
  end

  # #3175 Accept spaces before )'s in envelopes
  test "parse trailing spaces in envelopes" do
    response = "* 8 FETCH (FLAGS (\\Seen) UID 141433 RFC822.SIZE 109945 ENVELOPE (\"Sat, 15 Oct 2005 21:28:32 -0500\" \"Emailing: Oct.  2005 085\" ((\"Ken Meyer\" NIL \"k9kjm\" \"charter.net\")) ((\"Ken Meyer\" NIL \"k9kjm\" \"charter.net\")) ((\"Ken Meyer\" NIL \"k9kjm\" \"charter.net\")) ((NIL NIL \"Undisclosed-Recipient\" NIL )) NIL NIL NIL \"<002f01c5d1f9$4e1ca850$7a00a8c0@utility>\") BODY[HEADER.FIELDS (X-AUTOREPLY AUTO-SUBMITTED LIST-ID X-FACEBOOK-NOTIFY X-TWITTERSENDERID DELIVERED-TO)] {2}\r\n\r\n)\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
  end

  test "parse list response with unescaped quotes in mailbox name" do
    response = "* LIST (\\HasNoChildren) \"/\" \"INBOX/AFSB/2011 AFSB Platform Update/Features to Add/New Cart \"See your Shipping Charges\"\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
  end

  test "flatten_search_responses" do
    imap = UidValidityTester.new()

    multi_line_responses = [[1], [2], [9]]
    flattened = imap.flatten_search_responses(multi_line_responses)
    assert_equal [1, 2, 9], flattened
    assert_equal 3, flattened.size

    assert_nil imap.flatten_search_responses(nil)
    assert_nil imap.flatten_search_responses([])
    assert_equal [99], imap.flatten_search_responses([99])
  end

  test "send_command coverts closed stream IOErrror to ClosedConnectionError" do
    class StubImap < Net::IMAP
      def initialize
      end
    end
    stub_imap = StubImap.new
    ioerror = IOError.new("closed stream")
    stub_imap.expects(:send_command_without_retry).raises(ioerror)
    assert_raise Net::IMAP::ClosedConnectionError do
      stub_imap.send(:send_command, "")
    end
  end

  test "get_response buffer handling" do
    imap = UidValidityTester.new
    sock = mock("DummySocket")
    imap.instance_variable_set(:@sock, sock)

    parser = mock("DummyParser")
    imap.instance_variable_set(:@parser, parser)

    # Note the final "\r\n" is returned after the sock.read
    read_returns = ["First line", "\r\n", "X" * 10, "XX\r\n", "joe", "\r", "\nfoo{10}\r\n1234567890\r\n", "bar{10}\r\n1234567", "\r\n"]
    expected_lines = ["First line\r\n", "#{'X' * 12}\r\n", "joe\r\n", "foo{10}\r\n1234567890\r\n", "bar{10}\r\n123456789A\r\n"]
    sock.expects(:read).with(3).returns("89A")

    # Simulate readpartial returning less than a full buffer
    sock.expects(:readpartial).times(read_returns.size).returns(*read_returns)
    expected_lines.each_with_index do |line, i|
      parser.expects(:parse).with(line).returns(i)
    end

    assert_equal 0, imap.get_response_without_rails_logging
    assert_equal 1, imap.get_response_without_rails_logging
    assert_equal 2, imap.get_response_without_rails_logging
    assert_equal 3, imap.get_response_without_rails_logging
    assert_equal 4, imap.get_response_without_rails_logging
  end

  test "receive_responses creates tagged bye response" do
    begin
      server = TCPServer.new(nil, 0)
      server_port = server.addr[1]
      server_thread = Thread.start do
        Thread.current.abort_on_exception = true
        client = server.accept
        client.print "* OK IMAP4 ready\r\n"
        capability_tag = client.readline.split.first
        client.print "* CAPABILITY IMAP4rev1 LOGIN\r\n"
        client.print "#{capability_tag} OK done\r\n"
        login_tag = client.readline.split.first
        client.print "#{login_tag} OK logged in\r\n"
        logout_cmd = client.readline
        assert logout_cmd =~ /LOGOUT/i
        client.print "* BYE now\r\n"
        client.close
      end

      imap = Net::IMAP.new(nil, server_port, false)
      imap.login('x', 'y')
      imap.logout
    ensure
      server_thread.join(1) if server_thread
    end
  end

  test "parse escaped parenthese in mailbox names" do
    response = "* LIST (\\HasNoChildren) \"/\" \"joe - \\( two parens\\)\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "joe - ( two parens)", parsed_response.data.name

    response = "* LIST (\\HasNoChildren) \"/\" joe -(j)\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
  end

  test "parse_namespace_response handles invalid input" do
    assert_raise Net::IMAP::ResponseParseError do
      Net::IMAP::ResponseParser.new.parse_namespace_response( 'invalid' )
    end
  end

  test "parse list response with trailing space in mailbox names" do
    response = "* LIST () \"/\" \"Inbox\" \r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "Inbox", parsed_response.data.name
  end

  test "parse select response" do
    response = "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen OIB-Seen-OIB/Mailing Lists/GIH Global OIB-Seen-OIB/Business OIB-Seen-OIB/Mailing Lists $NotJunk OIB-Seen-OIB/News Forwarded OIB-Seen-OIB/Forwarders/Adnan OIB-Seen-OIB/Jobs OIB-Seen-OIB/Media OIB-Seen-OIB/Mailing Lists/Arab Advisors OIB-Seen-[Gmail]/Trash OIB-Seen-OIB/Forum/Fitness JunkRecorded OIB-Seen-OIB/Mailing Lists/Travel Mailing Lists OIB-Seen-OIB/Entertainment OIB-Seen-OIB/Dropbox.com OIB-Seen-OIB/Blog/pendolino.posterous.com OIB-Seen-[Gmail]/Spam OIB-Seen-OIB/Forum OIB-Seen-OIB/Mailing Lists/GroupOn OIB-Seen-OIB/Finance OIB-Seen-OIB/Mailing Lists/GoodReads OIB-Seen-OIB/Home/Home Brother MFC Status OIB-Seen-OIB/Forwarders/Deech OIB-Seen-[Gmail]/All Mail OIB-Seen-OIB/Aramex ShopnShip OIB-Seen-OIB/Podio (Work) $Junk OIB-Seen-OIB/Home $Forwarded NotJunk OIB-Seen-OIB/Communication OIB-Seen-OIB/Groups)\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
  end

  test "parse select permanentflags response" do
    response = "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen OIB-Seen-OIB/Mailing Lists/GIH Global OIB-Seen-OIB/Business OIB-Seen-OIB/Mailing Lists $NotJunk OIB-Seen-OIB/News Forwarded OIB-Seen-OIB/Forwarders/Adnan OIB-Seen-OIB/Jobs OIB-Seen-OIB/Media OIB-Seen-OIB/Mailing Lists/Arab Advisors OIB-Seen-[Gmail]/Trash OIB-Seen-OIB/Forum/Fitness JunkRecorded OIB-Seen-OIB/Mailing Lists/Travel Mailing Lists OIB-Seen-OIB/Entertainment OIB-Seen-OIB/Dropbox.com OIB-Seen-OIB/Blog/pendolino.posterous.com OIB-Seen-[Gmail]/Spam OIB-Seen-OIB/Forum OIB-Seen-OIB/Mailing Lists/GroupOn OIB-Seen-OIB/Finance OIB-Seen-OIB/Mailing Lists/GoodReads OIB-Seen-OIB/Home/Home Brother MFC Status OIB-Seen-OIB/Forwarders/Deech OIB-Seen-[Gmail]/All Mail OIB-Seen-OIB/Aramex ShopnShip OIB-Seen-OIB/Podio (Work) $Junk OIB-Seen-OIB/Home $Forwarded NotJunk OIB-Seen-OIB/Communication OIB-Seen-OIB/Groups \\*)] Flags permitted.\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "PERMANENTFLAGS", parsed_response.data.code.name
  end

  test "parse bad mailbox literal response" do
    response = "* LIST (\\HasNoChildren) \".\" {40}\r\nArchive.Hippos les en Sportbad de Beeck\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "Archive.Hippos les en Sportbad de Beeck", parsed_response.data.name
  end

  test "parse capability response with 8 bit character" do
    response = "* CAPABILITY  IMAP4REV1 STARTTLS AUTH=LOGIN\xFF\r\n"
    response.force_encoding(Encoding::ASCII_8BIT)
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal ['IMAP4REV1', 'STARTTLS', 'AUTH=LOGIN'], parsed_response.data
  end

  test "parse list response with unescaped slash SB-6998" do
    response = "* LIST (\\HasNoChildren) \"/\" \"important\\passwords\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "important\\passwords", parsed_response.data.name
  end

  test "allow quoted \ before parenthesis SB-7934" do
    response = "* LIST (\\HasNoChildren) \"/\" \"z(\\\\)\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
    assert_equal "z(\\)", parsed_response.data.name
  end

  test "parse escaped asterisk SB-7200" do
    response = "* LIST (\\Unmarked) \"/\" \"Cabinet/\\*blocked keywords\"\r\n" 
    parsed_response = Net::IMAP::ResponseParser.new.parse(response)
  end

  test "ensure_nz_number accepts invalid large uids SB-7204" do
    set = Net::IMAP::MessageSet.new(18446744073709551615)
    assert_nothing_raised { set.validate }
  end

  test "serialize ascii-8bit mailboxes" do
    address = Net::IMAP::Address.from_hash( :mailbox => "Caf\xC3\xA9CupSale".force_encoding( Encoding::ASCII_8BIT ), :host => 'cutscheaped.eu', :name => "Caf\xC3\xA9 Cup Sale".force_encoding( Encoding::ASCII_8BIT ) ) 
    assert_equal "CaféCupSale@cutscheaped.eu", address.serialize( :include_name => false )
    assert_equal "Café Cup Sale <CaféCupSale@cutscheaped.eu>", address.serialize( :include_name => true )
  end

  test "initialize with a hardcoded ssl_version" do
    socket = mock("socket")
    Net::IMAP.any_instance.expects(:open_socket).returns( socket )
    Net::IMAP.any_instance.expects(:start_tls_session).with( { :ssl_version=>:TEST_TLS, :verify_mode => 1 } ).raises(OpenSSL::SSL::SSLError.new).once
    assert_raise OpenSSL::SSL::SSLError do
      Net::IMAP.new('imap.test', { :port => 993, :ssl => { :ssl_version => :TEST_TLS, :verify_mode => 1 } }, true)
    end
  end

  test "initialize calls start_tls_session with different TLS types" do
    socket = mock("socket")
    socket.expects(:close).twice
    Net::IMAP.any_instance.expects(:open_socket).at_least_once.returns( socket )

    Net::IMAP.any_instance.expects(:start_tls_session).with( {:verify_mode=>0} ).raises(OpenSSL::SSL::SSLError.new).once
    Net::IMAP.any_instance.expects(:start_tls_session).with( {:ssl_version => :TLSv1, :verify_mode=>0} ).raises(OpenSSL::SSL::SSLError.new).once
    Net::IMAP.any_instance.expects(:start_tls_session).with( {:ssl_version => :SSLv3_client, :verify_mode=>0} ).raises(OpenSSL::SSL::SSLError.new).once

    assert_raise OpenSSL::SSL::SSLError do
      Net::IMAP.new('imap.test', 993, true)
    end
  end

  test "disable directs call to imap delete by undefining the method" do
    Net::IMAP.any_instance.expects(:open_socket)
    Net::IMAP.any_instance.stubs(:get_response).returns(Net::IMAP::UntaggedResponse.new)
    imap = Net::IMAP.new('test.host')
    assert_raise NoMethodError do
      imap.delete
    end
  end

  test "parses escaped square bracket in quoted string" do
    response = "* LIST (\\Marked) \"/\" \"INBOX/[Suspected Spam\\]\"\r\n"
    parsed_response = Net::IMAP::ResponseParser.new.parse( response )
    assert_equal 'INBOX/[Suspected Spam]', parsed_response.data.name
  end

end
