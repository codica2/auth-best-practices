# Token-based Authentication Best Practices

![Codica logo](images/jwt-rails-banner.jpg)

## What Does a JWT Token Contain?

The token is separated into three base-64 encoded, dot-separated values. Each value represents a different type of data:

### Header
Consists of the type of the token (JWT) and the type of encryption algorithm (HS256) encoded in base-64.

### Payload
The payload contains information about the user and his or her role. For example, the payload of the token can contain the e-mail and the password.

### Signature
Signature is a unique key that identifies the service which creates the header. In this case, the signature of the token will be a base-64 encoded version of the Rails application's secret key (`Rails.application.credentials.secret_key_base`). Because each application has a unique base key, this secret key serves as the token signature.

### This application uses the next gems:

- [bcrypt](https://github.com/codahale/bcrypt-ruby)
- [jwt](https://github.com/jwt/ruby-jwt)
- [simple_command](https://github.com/nebulab/simple_command)

## Setting up a Token-based Authentication

### Generate User model

```ruby
rails g model User name email password_digest
```

### Install `bcrypt` gem 

The method `has_secure_password` must be added to the model to make sure the password is properly encrypted into the database: `has_secure_password` is part of the `bcrypt` gem, so we have to install it first. Add it to the gemfile:

```ruby
# Gemfile

gem 'bcrypt', '~> 3.1.7'
```

### Model preparations

Include `has_secure_password` and method `to_token_payload` into the model.
In the `payload` hash you can specify any meta data you want to pass into token such as `role`, `first_login?` etc 

```ruby
# app/models/user.rb

class User < ApplicationRecord

  has_secure_password

  def to_token_payload
    {
      id: id,
      role: role
    }
  end

end
```

### Encoding and Decoding JWT Tokens

Once the user model is done, the implementation of the JWT token generation can start. First, the jwt gem will make encoding and decoding of HMACSHA256 tokens available in the Rails application.

```ruby
# Gemfile

gem 'jwt'
```

Once the gem is installed, it can be accessed through the JWT global variable. Because the methods that are going to be used to require encapsulation, a singleton class is a great way of wrapping the logic and using it in other constructs.

```ruby
require 'jwt'

class JsonWebToken

  class << self

    SECRET_KEY = Rails.application.credentials.secret_key_base

    def encode(payload)
      payload.reverse_merge!(meta)

      JWT.encode(payload, SECRET_KEY)
    end

    def decode(token)
      JWT.decode(token, SECRET_KEY).first
    end

    def meta
      { exp: 7.days.from_now.to_i }
    end

  end

end
```

To make sure everything will work, the contents of the `lib` directory have to be included when the Rails application loads.

```ruby
# config/application.rb
module Api
  class Application < Rails::Application
    #.....
    config.autoload_paths << Rails.root.join('lib')
    #.....
  end
end
```


### Authenticating Users

Instead of using private controller methods, `simple_command` can be used. For more information about installation, check out the article `simple_command`.

```ruby
# Gemfile

gem 'simple_command'
```

Then, the alias methods of the `simple_command` can be easily used in a class by writing `prepend SimpleCommand`. The command takes the user's e-mail and password then returns the user, if the credentials match. Here is how this can be done:

```ruby
# app/auth/authenticate_user.rb
require 'json_web_token'

class AuthenticateUser

  prepend SimpleCommand
  attr_accessor :email, :password

  def initialize(email, password)
    @email = email
    @password = password
  end

  def call
    return unless user

    JsonWebToken.encode(user_id: user.id, aud: user.role)
  end

  private

  def user
    current_user = User.find_by(email: email)

    return current_user if current_user && current_user.authenticate(password)

    errors.add(:user_authentication, 'Invalid credentials')
  end
end
```

### Checking User Authorization

The token creation is done, but there is no way to check if a token that's been appended to a request is valid. The command for authorization has to take the `headers` of the request and decode the token using the `decode` method in the `JsonWebToken` singleton.

```ruby
# app/auth/authorize_api_request.rb
class AuthorizeApiRequest

  prepend SimpleCommand

  def initialize(headers = {})
    @headers = headers
  end

  def call
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    @user || errors.add(:token, 'Invalid token')
  end

  private

  attr_reader :headers

  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
  end

  def http_auth_header
    return headers['Authorization'].split(' ').last if headers['Authorization'].present?

    errors.add(:token, 'Missing token')
  end

end

```

### Authorizing Requests

To put the token to use, there must be a `current_user` method that will 'persist' the user. In order to have `current_user` available to all controllers, it has to be declared in the `ApiController`:

```ruby
module Api

  module V1

    class ApiController < ActionController::API

      before_action :authenticate_request

      attr_reader   :current_user

      private

      def token
        JsonWebToken.decode(request.headers['Authorization'])
      end

      def user
        User.find(token[:user_id])
      end

      def authenticate_request
        @current_user = AuthorizeApiRequest.call(request.headers).result
        return if @current_user

        json_responce({ errors: 'Not Authorized' }, :unauthorized)
      end

    end
  end
end  
```

### Implementing Helper Methods into the Controllers

Login Users

```ruby

module Api

  module V1

    class AuthenticationController < ApiController

      skip_before_action :authenticate_request, only: :login

      def login
        authenticate params[:email], params[:password]
      end

      private

      def authenticate(email, password)
        command = AuthenticateUser.call(email, password)

        if command.success?
          render json: {
            access_token: command.result,
            message: 'Login Successful'
          }
        else
          render json: { error: command.errors }, status: :unauthorized
        end
      end

    end

  end

end

```

The `authenticate` action will take the JSON parameters for email and password through the `params` hash and pass them to the `AuthenticateUser` command. If the command succeeds, it will send the JWT token back to the user.

```ruby
# config/routes.rb
scope :auth do
  post '/login', to: 'authentication#login'
end
```

### Testing via Rspec

To check the token authentication in work we should create `rspec` test for `AuthenticationController`. Here is an example of testing `login` action

```ruby

resource 'Authentication' do

  let!(:user) { create :user }

  before do
    header 'Accept',       'application/json'
    header 'Content-Type', 'application/json; charset=utf-8'
  end

  post '/api/v1/auth/login' do
    parameter :email,             'User email'
    parameter :password,          'User password'

    context '200' do
      let(:email)  { user.email }
      let(:password) { user.password }

      let(:raw_post) { params.to_json }

      example_request 'Login user' do
        expect(status).to eq(200)
      end
    end

    context '401' do
      let(:email) { user.email }
      let(:password) { 'wrongpass' }

      let(:raw_post) { params.to_json }

      example_request 'Failed user login' do
        expect(status).to eq(401)
        expect(JSON.parse(response_body)).to eq(
          'error' => {
            'user_authentication' => 'Invalid credentials'
          }
        )
      end
    end
  end
end

```

To check other actions that required the user authentication you can use the following code:


```ruby
resource 'Users' do

  let!(:user) { create :user }

  let!(:id) { user.id }

  before do
    header 'Accept',       'application/json'
    header 'Content-Type', 'application/json; charset=utf-8'
  end

  put '/api/v1/users/:id' do

    with_options scope: :user do
      parameter :email
      parameter :first_name
      parameter :last_name
    end

    let(:first_name) { Faker::Name.first_name }
    let(:last_name) { Faker::Name.last_name }

    context '200' do

      before do 
        header 'Authorization', "Bearer #{JsonWebToken.encode({ user_id: user.id, aud: user.role})}"
      end

      let(:raw_post) { params.to_json }

      example_request 'User updates itself' do
        expect(status).to eq(200)
      end
    end
  end
end
```

You need to pass user data into `JsonWebToken.encode` method to generate `Authorization Bearer` token in `before` block in your test. 


## License  
Timebot is Copyright © 2015-2020 Codica. It is released under the [MIT License](https://opensource.org/licenses/MIT).  
  
## About Codica  
  
[![Codica logo](https://www.codica.com/assets/images/logo/logo.svg)](https://www.codica.com)

The names and logos for Codica are trademarks of Codica.
  
We love open source software! See [our other projects](https://github.com/codica2) or [hire us](https://www.codica.com/) to design, develop, and grow your product.