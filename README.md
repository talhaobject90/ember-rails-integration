# ember-rails-integration

RAILS INTEGRATION
--------------------
1. Devise and authentication
```

rails _5.0.0.beta3_ new bookstore-api --api
rails generate devise:install
rails generate devise user
t.string :authentication_token, null: false, default: ""



//config/routes.rb
devise_for :users, controllers: { sessions: 'sessions' }

//controllers/application_controller.rb

class ApplicationController < ActionController::Base

  before_filter :authenticate_user_from_token!

  before_filter :authenticate_user!
#  before_filter :set_paper_trail_whodunnit



// incase of heroku install error include this post-script
"scripts": {

    "postinstall": "cd node_modules/ember-lodash && npm install",
  },

  private

    def authenticate_user_from_token!
      authenticate_with_http_token do |token, options|
        user_email = options[:email].presence
        user = user_email && User.find_by_email(user_email)

        if user && Devise.secure_compare(user.authentication_token, token)
          sign_in user, store: false
        end
      end
    end
end



//controllers/sessions_controller.rb

class SessionsController < Devise::SessionsController
  respond_to :json

   # POST /api/users/sign_in
   def create
     respond_to do |format|
       format.json do
         self.resource = warden.authenticate!(auth_options)
         data = {
           user_id: resource.id,
           token: resource.authentication_token,
           email: resource.email
         }
         render json: data, status: :created

       end
     end
   end
end




models/users.rb
class User < ActiveRecord::Base
  before_save :ensure_authentication_token

  devise :database_authenticatable, :recoverable, :trackable, :validatable

  # Generate a token for this user if one does not already exist
  def ensure_authentication_token
    if authentication_token.blank?
      self.authentication_token = generate_authentication_token
    end
  end

  # Identical to above except it saves the user
  def ensure_authentication_token!
    ensure_authentication_token
    save
    end

  # Forces a new authentication token to be generated for this user and saves it
  # to the database
  def reset_authentication_token!
    self.authentication_token = generate_authentication_token
    save
  end

  private

  def generate_authentication_token
    loop do
      token = Devise.friendly_token
      break token unless User.find_by(authentication_token: token)
    end
  end
end


db/seeds.rb
User.create(email: 'admin@test.com', password: 'password')


config/initializers/json_api.rb
ActiveModel::Serializer.config.adapter = ActiveModel::Serializer::Adapter::JsonApi







EMBER
------------------
ENV.APP.host =  'http://localhost:3000';

    contentSecurityPolicy: {
      'default-src': "'self' *",
      'script-src': "'self' 'unsafe-inline' *",
      'connect-src': "'self' *",
      'font-src': "'self'  data: http://fonts.gstatic.com * ",
      'media-src': "'self' *",
      'style-src': "'self' 'unsafe-inline' *",
      'img-src' : "'self' data: http://fonts.gstatic.com *"
    },


ember install ember-simple-auth
  ENV['simple-auth-devise'] = {
    tokenAttributeName: 'token',
    identificationAttributeName: 'email',
    serverTokenEndpoint:  ENV.APP.host  + '/users/sign_in',
    authorizer: 'devise',
    crossOriginWhitelist: ['*'],
  };

ENV['ember-simple-auth'] = {
    authenticationRoute: 'login',
    routeAfterAuthentication: 'dashboard',
    routeIfAlreadyAuthenticated: 'dashboard'
  };

// controllers/login.js
import Ember from 'ember';



export default Ember.Controller.extend(Ember.Evented,{

session: Ember.inject.service('session'),


  isLoginButtonDisabled: Ember.computed('email', function() {
    return Ember.isEmpty(this.get('email'));
  }),

  actions: {
    authenticate(){
      var controller = this;
        this.get('session').authenticate('authenticator:devise', this.get('email'), this.get('password')).catch(function(){

          controller.notifications.addNotification({
            message: 'Username or password is incorrect!' ,
            type: 'error',
            autoClear: true
          });
        });
    }
  }
});


//routes/login.js
import Ember from 'ember';
import UnauthenticatedRouteMixin from 'ember-simple-auth/mixins/unauthenticated-route-mixin';

export default Ember.Route.extend(UnauthenticatedRouteMixin);



//routes/application.js

import Ember from 'ember';

import ApplicationRouteMixin from 'ember-simple-auth/mixins/application-route-mixin';
export default Ember.Route.extend(ApplicationRouteMixin, {
  });



app/authenticators/devise.js
import ENV from '../config/environment';
import DeviseAuthenticator from 'ember-simple-auth/authenticators/devise';

export default DeviseAuthenticator.extend({
  serverTokenEndpoint: ENV.APP.host + '/users/sign_in'
});


app/authorizers/devise.js
import DeviseAuthorizer from 'ember-simple-auth/authorizers/devise';

export default DeviseAuthorizer.extend({
  actions: {
    authorize: function(){
      this.get('session').authorize('authorizer:devise', () => {
      });
    }
  }
});

ember install ember-cli-notifications

app/config/adapters/application.js
import DS from 'ember-data';
import ENV from '../config/environment';
import DataAdapterMixin from 'ember-simple-auth/mixins/data-adapter-mixin';

export default DS.JSONAPIAdapter.extend(DataAdapterMixin,{
  host: ENV.APP.host,
  authorizer: 'authorizer:devise'
});


app/config/serializers/application.js

import DS from 'ember-data';
export default DS.JSONAPISerializer.extend({
  serialize() {
    const result = this._super(...arguments),
    attr = result.data.attributes,
    rel = result.data.relationships;
    if(rel){
      return Object.keys(rel).reduce(function(acc, elem) {
        const data = rel[elem].data;
        if (data) {
          acc[elem + "_id"] = data.id;
        }
        if (data && data.type) {
          acc[elem + "_type"] = data.type[0].toUpperCase() + data.type.slice(1, -1);
        }
        return acc;
      }, attr);
    }
    else{
      return (rel,attr);
    }
  }
});



app/templates/dashboard.hbs
  {{#link-to class="item"}}
  <i class="logout icon" {{action "logout"}}></i>
  Logout
  {{/link-to}}
  
  
app/routes/dashboard.js
import Ember from 'ember';
import AuthenticatedRouteMixin from 'ember-simple-auth/mixins/authenticated-route-mixin';

export default Ember.Route.extend(AuthenticatedRouteMixin,{

session: Ember.inject.service('session'),

  actions: {
    logout() {

      this.get('session').invalidate();
      this.transitionTo('login');
    }
  }
});

app/routes/application.js
import Ember from 'ember';
import ApplicationRouteMixin from 'ember-simple-auth/mixins/application-route-mixin';

export default Ember.Route.extend(ApplicationRouteMixin, {
});






