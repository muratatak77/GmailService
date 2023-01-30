module ImapConstants

  SPECIAL_USE_ATTRIBUTES = [ :All, :Archive, :Drafts, :Flagged, :Junk, :Sent, :Trash, :Important ]

  # SB-6642
  # http://people.dsv.su.se/~jpalme/ietf/ietf-mail-attributes.html#Heading14
  HEADER_PRIORITY_HIGHEST = 1
  HEADER_PRIORITY_HIGH    = 2
  HEADER_PRIORITY_NORMAL  = 3
  HEADER_PRIORITY_LOW     = 4
  HEADER_PRIORITY_LOWEST  = 5
  
  HEADER_PRIORITY_LOWEST_STR     = "lowest"
  HEADER_PRIORITY_LOW_STR        = "low"
  HEADER_PRIORITY_NORMAL_STR     = "normal"
  HEADER_PRIORITY_HIGH_STR       = "high"
  HEADER_PRIORITY_HIGHEST_STR    = "highest"
  HEADER_PRIORITY_URGENT_STR     = "urgent"
  HEADER_PRIORITY_NON_URGENT_STR = "non-urgent"

  MISSING_HOST_NAME = '.MISSING-HOST-NAME.'

  HOTMAIL_RETRY_IGNORE_REGEX = /Error \d+/
  SOME_REQUESTED_MESSAGES_REGEX = /Some of the requested messages no longer exist/

  OFFICE_365_NOT_AUTHENTICATED_REGEX = /User is authenticated but not connected/i 

  UIDNEXT = "UIDNEXT"
  QUOTA_ERROR_REGEX = Regexp.union( /quota/i,
                                    /mailbox is full/i ,
                                    /There is not enough space in the destination folder to copy the specified messages/i ,
                                    /The mailbox does not have enough space remaining to complete this operation/i ,
                                    /Mailspace is full/i ,
                                    /UID max mailbox size exceeded/i ,
                                    /Not enough disk space/i ,
                                    /Store partition is full/i )

  module Header
    AUTO_REPLY = "X-Autoreply"
    AUTO_REPLY_NORMALIZED = AUTO_REPLY.downcase

    AUTO_SUBMITTED = "Auto-Submitted"
    AUTO_SUBMITTED_NORMALIZED = AUTO_SUBMITTED.downcase

    FACEBOOK_NOTIFY = "X-Facebook-Notify"
    FACEBOOK_NOTIFY_NORMALIZED = FACEBOOK_NOTIFY.downcase

    TWITTER_SENDER_ID = "X-Twittersenderid"
    TWITTER_SENDER_ID_NORMALIZED = TWITTER_SENDER_ID.downcase

    LIST_ID = "List-Id"
    LIST_ID_NORMALIZED = LIST_ID.downcase

    LIST_UNSUBSCRIBE = "List-Unsubscribe"
    LIST_UNSUBSCRIBE_NORMALIZED = LIST_UNSUBSCRIBE.downcase

    DELIVERED_TO = "Delivered-To"
    DELIVERED_TO_NORMALIZED = DELIVERED_TO.downcase

    SANEBOX_ATTACH = 'X-Sanebox-Attach'
    SANEBOX_ATTACH_NORMALIZED = SANEBOX_ATTACH.downcase

    SANEBOX_HOLD = 'X-Sanebox-Hold'
    SANEBOX_HOLD_NORMALIZED = SANEBOX_HOLD.downcase

    REFERENCES = 'References'
    REFERENCES_NORMALIZED = REFERENCES.downcase

    RECEIVED = "Received"
    RECEIVED_NORMALIZED = RECEIVED.downcase

    RESENT_DATE = "Resent-Date"
    RESENT_DATE_NORMALIZED = RESENT_DATE.downcase

    PRIORITY = "Priority"
    PRIORITY_NORMALIZED = PRIORITY.downcase

    X_PRIORITY = "X-Priority"
    X_PRIORITY_NORMALIZED = X_PRIORITY.downcase

    IMPORTANCE = "Importance"
    IMPORTANCE_NORMALIZED = IMPORTANCE.downcase

    X_ORIGINAL_FROM = "X-Original-From"
    X_ORIGINAL_FROM_NORMALIZED = X_ORIGINAL_FROM.downcase

    X_ORIGINAL_SENDER = "X-Original-Sender"
    X_ORIGINAL_SENDER_NORMALIZED = X_ORIGINAL_SENDER.downcase

    X_BEEN_THERE = "X-BeenThere"
    X_BEEN_THERE_NORMALIZED = X_BEEN_THERE.downcase
  end

  module FetchItem
    def self.peekify(s)
      s.gsub(/BODY\[/, 'BODY.PEEK[')
    end

    BODY = 'BODY[]'
    FETCH_FROM_ADDRESS = 'BODY[HEADER.FIELDS (FROM)]'
    FETCH_FROM_ADDRESS_PEEK = peekify(FETCH_FROM_ADDRESS)

    RFC822_SIZE = 'RFC822.SIZE'
    FETCH_FLAGS = 'FLAGS'
    FETCH_ENVELOPE = 'ENVELOPE'
    FETCH_INTERNALDATE = 'INTERNALDATE'
    FETCH_MESSAGE_ID = 'BODY[HEADER.FIELDS (MESSAGE-ID)]'
    FETCH_MESSAGE_ID_PEEK = peekify(FETCH_MESSAGE_ID)

    # Update config/initializers/net_imap.rb if this is changed. Search for
    # @@token_name_cache or ImapAccountCache::STANDARD_FETCH_LIST
    STANDARD_HEADERS = [ Header::AUTO_REPLY, Header::AUTO_SUBMITTED, Header::LIST_ID, Header::LIST_UNSUBSCRIBE, 
      Header::FACEBOOK_NOTIFY, Header::TWITTER_SENDER_ID, Header::DELIVERED_TO, Header::REFERENCES, 
      Header::SANEBOX_ATTACH, Header::RECEIVED, Header::IMPORTANCE, Header::PRIORITY,
      Header::X_PRIORITY, Header::X_ORIGINAL_FROM, Header::X_ORIGINAL_SENDER, Header::SANEBOX_HOLD,
      Header::RESENT_DATE, Header::X_BEEN_THERE
    ]
    FETCH_HEADERS = 'BODY[HEADER.FIELDS (' + STANDARD_HEADERS.map(&:upcase).join(' ') + ')]'
    FETCH_HEADERS_PEEK = peekify(FETCH_HEADERS).freeze

    # Not a real IMAP attribute, but used to store the training_checked flag
    TRAINING_CHECKED = "TC".freeze

    FETCH_LIST_UNSUBSCRIBE = 'BODY[HEADER.FIELDS (LIST-UNSUBSCRIBE)]'
    FETCH_LIST_UNSUBSCRIBE_PEEK = peekify(FETCH_LIST_UNSUBSCRIBE)

    # Update config/initializers/net_imap.rb if this is changed. Search for
    # @@token_name_cache or ImapAccountCache::STANDARD_FETCH_LIST
    STANDARD_FETCH_LIST = [FETCH_FLAGS, RFC822_SIZE, FETCH_HEADERS_PEEK, FETCH_INTERNALDATE, FETCH_ENVELOPE]
    STANDARD_FETCH_LIST_NO_HEADERS = STANDARD_FETCH_LIST - [FETCH_HEADERS_PEEK]
    BODY_PEEK = peekify(BODY).freeze

    SEEN_FLAG = :Seen
    DELETED_FLAG = :Deleted
    HAS_NO_CHILDREND_FLAG = :Hasnochildren
    FLAGGED_FLAG = :Flagged
    DRAFT = :Draft
  end

  module FolderPrefix
    GMAIL = 'Gmail'
    GOOGLE_MAIL = 'Google Mail'
  end
end
