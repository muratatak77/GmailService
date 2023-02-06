class MessagesController < ApplicationController
  require 'google_oauth2'
  require 'google/apis/gmail_v1'

  PER_PAGINATE = 10
  MAX_MESSAGE_SIZE = 100

  # if we don't have a specific page token , just will be load first 10 messages and details
  # if we use specific page token we can fetch just for page token.
  def index
    @page_tokens = load_page_tokens
    @page = params[:page]
    gmail = authenticated_client(account)
    using_page_token = params[:page_token]
    result = if using_page_token
               gmail.list_user_messages('me', max_results: PER_PAGINATE, label_ids: 'INBOX', page_token: using_page_token)
             else
               gmail.list_user_messages('me', max_results: PER_PAGINATE, label_ids: 'INBOX')
             end
    load_message_detail(result)
  end

  private
 
  def load_message_detail(result)
    message_details = []
    result.messages.each do |item|
      id, from, to, cc, subject = get_from_cache(item.id)
      message_details << { message_id: id, from: from, to: to, cc: cc, subject: subject }
    end
    @messages = group_by_form(message_details)
  end

  def group_by_form(data)
    result = {}
    data.group_by { |item| item[:from] }.map { |k, v| result[k] = v }
    result
  end

  # Getting just page tokens till MAX_MESSAGE_SIZE : 100, and just 1 fetch will be enough
  def load_page_tokens
    Rails.cache.fetch("page_tokens_cache_by_#{account.id}_#{account.updated_at}", expires_in: 1.hour) do
      load_all_page_tokens_by_account(account)
    end
  end

  def load_all_page_tokens_by_account(account)
    gmail = authenticated_client(account)
    message_size = 0
    next_page = nil
    page_tokens = []
    begin
      result = gmail.list_user_messages('me', max_results: PER_PAGINATE, page_token: next_page)
      message_size += result.messages.size
      break if message_size >= MAX_MESSAGE_SIZE

      next_page = result.next_page_token
      page_tokens << next_page
    end while next_page
    page_tokens
  end

  # A Message detail will not be change in our mail box. Caching will be very efective solution.
  def get_from_cache(id)
    Rails.cache.fetch("message_header_detail_by_message_#{id}") do
      get(id)
    end
  end

  def get(id)
    gmail = authenticated_client(account)
    return nil if gmail.nil?

    result = gmail.get_user_message('me', id)
    payload = result.payload
    headers = payload.headers

    from = headers.any? { |h| h.name == 'From' } ? headers.find { |h| h.name == 'From' }.value : ''
    to = headers.any? { |h| h.name == 'To' } ? headers.find { |h| h.name == 'To' }.value : ''
    cc = headers.any? { |h| h.name == 'Cc' } ? headers.find { |h| h.name == 'Cc' }.value : ''
    subject = headers.any? { |h| h.name == 'Subject' } ? headers.find { |h| h.name == 'Subject' }.value : ''
    [id, from, to, cc, subject]
  end

  def authenticated_client(account)
    gmail = Google::Apis::GmailV1::GmailService.new
    gmail.authorization = client(account).authenticated_client
    redirect_to controller: :oauth, action: :index if gmail.nil?
    gmail
  end

  def client(account)
    @client ||= GoogleOauth2.new(account)
  end

  def account
    @account ||= Account.last
  end
end
