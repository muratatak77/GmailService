# Welcome

You should receive a request to share a repository on GitHub. The repository contains the code for your programming test. You will need to have a development environment in which you can install Rails to work on the test.

* Please find a time where can spend at least an hour working on the test.
* You should **not** spend more than 30 minutes setting up the environment to work on the test, contact us if you are having an issue.
* You are not necessarily expected to finish the test in the alloted time, but try to get as far as possible

Once you accept the share request, set up your computer to access GitHub.

After you checkout the repository:

    git clone ssh://github.com/sanebox/interview-%{email_url}.git

The repository you cloned contains the set up for your programming test.

This repository is set up to use Bundler. You may add any 3rd party gems that you find to be useful.

Using the [Gmail REST API][1], and the [Ruby Google API client][2], construct a web service that will list the contents of the users **INBOX**.

The messages should be neatly displayed and grouped by **From** address.  Use your own judgement for the final formatting, but don't get too caught up on making it pretty.

    First Last <email@addre.ss>

      To: <me@somewhere.com>
      Subject: Subject 1

      To: <other@address.com>
      Cc: <team@member.com>
      Subject: Subject 2

    Sender Number Two <other@person.com>

      To: <me@somewhere.com>
      Subject: Subject 3

      To: <another@address.com>
      Subject: Subject 4

When you're done, just push your code to the repository using your typical git
commands and drop me a note!

Some things to consider:

  * What can be done with lazy one-time initialization?
  * How many messages does a single call to the API fetch?  What if the INBOX has more than that?

## Some helpful hints

There is already a Project setup in the Google Developer Console for this task.
The registered callback URI is http://localhost:3000/google/oauth2/callback.
If, for some reason, you need a different URI please let me know.

You may initialize a new *unauthenticated* client using the following code:

    secrets = Google::Auth::ClientId.from_file(
          Rails.root.join('config/client_secret.json')
    )

    client = Google::Auth::UserRefreshCredentials.new(
        client_id: secrets.id,
        client_secret: secrets.secret,
        redirect_uri: 'http://localhost:3000/google/oauth2/callback',
        scope: 'https://www.googleapis.com/auth/gmail.readonly openid email profile'
    )

Familiarity with OAuth2 will be helpful with this task, so its best to take
some time to understand [this document][3].

**You will be populating the two endpoints in OauthController to handle the Oauth2 exchange.**

When you *do not have an access token*, you may redirect the user to the
following url:

    redirect_to client.authorization_uri.to_s

In your OauthController#callback you can get an access token using the
following snippet:

    client.code = params[:code]
    access_token_hash = client.fetch_access_token!

You may wish to save some data from the `access_token_hash` at this point into
the session or database.

Once you have credentials, you can initialize an authenticated client with:

    client = Google::Auth::UserRefreshCredentials.new(
        client_id: secrets.id,
        client_secret: secrets.secret,
        redirect_uri: 'http://localhost:3000/google/oauth2/callback',
        scope: 'https://www.googleapis.com/auth/gmail.readonly openid email profile',
        access_token: access_token_hash['access_token'],
        refresh_token: access_token_hash['refresh_token'],
        expires_at: Time.now + access_token_hash['expires_in']
    )

You can fetch the authenticated user's identity using the following request:

    identity = MultiJson.load(
        client.fetch_protected_resource(
          uri: 'https://people.googleapis.com/v1/people/me?personFields=emailAddresses,names'
        ).body
    )

Once you have completed the OAuth2 credential exchange you can make API
requests using the Gmail API:

    require 'google/apis/gmail_v1'
    gmail = Google::Apis::GmailV1::GmailService.new
    gmail.authorization = client
    gmail.list_user_labels( 'me' )

You can see a list of available API methods [here][4].

Good luck! If you get stuck, **please** feel free to ask me for help.  There
may be several additional pointers we can provide if you find yourself stuck
with some aspect of the OAuth2 credential exchange or API usage.

[1]: https://developers.google.com/gmail/api/reference/rest
[2]: https://github.com/googleapis/google-api-ruby-client
[3]: https://developers.google.com/identity/protocols/oauth2
[4]: https://googleapis.dev/ruby/google-apis-gmail_v1/v0.12.0/Google/Apis/GmailV1/GmailService.html
