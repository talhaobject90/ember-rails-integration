
> These are the results of my 4 months research . I am giving it away.

----------






# ember-rails-integration

##GIT BASIC COMMANDS

git clone ------ssh url-----


cd into directory

FOR RAILS 

bundle install

NB: sometimes you have to issue "bundle exec rake db:create" instead of just " rake db:create"

rake db:create 
rake db:migrate
rake db:seed
rails server

FOR EMBER 

npm install
bower install
ember server



After doing any changes.
1) To check you changed files list  - git status
2) To add newly created files to git  - git add .
3) To add commit changes  - git commit -m "comment"
4) To push  - git push origin master




##INSTALL HEROKU TOOLBELT
```

wget -O- https://toolbelt.heroku.com/install-ubuntu.sh | sh

ssh-keygen -t rsa -C "your_email@example.com"

heroku login

heroku keys:add

git remote add heroku git@heroku.com:project.git

//download db 

 heroku pg:backups capture
 curl -o latest.dump `heroku pg:backups public-url`
 
 php pg2mysql_cli.php /tmp/newpgdump.sql /tmp/newpgdump_mysql.sql 
ref  http://www.pukkapanel.com/guide29/convert-postgresql-dump-to-mysql


```
### incase of heroku install error include this post-script
```
// include this in package.json
"scripts": {
    "postinstall": "cd node_modules/ember-lodash && npm install",
  },
```

##INSTALL RAILS 
```
sudo apt-get install git-core curl zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev libcurl4-openssl-dev python-software-properties libffi-dev

cd
git clone git://github.com/sstephenson/rbenv.git .rbenv
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc

git clone git://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build 
echo 'export PATH="$HOME/.rbenv/plugins/ruby-build/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc


rbenv install -v 2.2.2
rbenv rehash
rbenv global 2.2.2
echo "gem: --no-document" > ~/.gemrc
gem install bundler
rbenv rehash
gem install rails --pre --no-ri --no-rdoc
rbenv rehash


sudo apt-get install libmysqlclient-dev
gem install mysql2 
sudo apt-get install libpq-dev
```


##INSTALL EMBER


```
curl -sL https://deb.nodesource.com/setup_5.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -g ember-cli
sudo npm install -g bower
```

###INSTALL NPM PACKAGE DIRECTLY FROM GITHUB
```
npm install git+https://git@github.com/talhaobject90/ember-cli-selectize.git --save-dev

```
 


##RAILS INTEGRATION


###New Rails 
```
rails _5.0.0.beta3_ new bookstore-api --api
```
### Devise
```
rails generate devise:install
rails generate devise user
```
####Add to migration file
```
t.string :authentication_token, null: false, default: ""
```

```
//config/routes.rb
devise_for :users, controllers: { sessions: 'sessions' }
```
```
//controllers/application_controller.rb
class ApplicationController < ActionController::Base
  before_filter :authenticate_user_from_token!
  before_filter :authenticate_user!

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
```
```
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
```
```
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
```

```
db/seeds.rb
User.create(email: 'admin@test.com', password: 'password')
```

##JSON API INITIALIZER & Register MIME TYPE
```
config/initializers/json_api.rb

ActiveModel::Serializer.config.adapter = ActiveModel::Serializer::Adapter::JsonApi
Mime::Type.register "application/json", :json, %w( text/x-json application/jsonrequest application/vnd.api+json )
```



## RAILS DROP AND RE MIGRATE DB
```
rake db:drop db:create db:migrate
```
##EMBER INTEGRATION
-----------------

###ENVIRONMENT JS FILE
```
// environment.js

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
```



### EMBER ROUTE MODEL HOOK AND SETUPCONTROLLER METHODS(WORKS MOSTLY FOR EMBER 2.4.*)

```

// TYPE 1: MODEL HOOK AND SETUP CONTROLLER
model: function() {
    return this.store.findAll('product' ,{reload: true});
  },

  setupController: function(controller ,model) {
    controller.set('products',model);
    controller.set('suppliers', this.store.findAll('supplier') ,{reload: true});
  },
  
  
  
// TYPE 2  : USING RSVP HASH


    model: function() {
      return Ember.RSVP.hash({
      product: this.modelFor('dashboard.inventory.product'),
      products: this.store.findAll('product'),
    });

    },

  setupController: function(controller ,model) {
    controller.set('product',model.product );
    controller.set('products', model.products);

  }
  
// TYPE 3: USING PARAMS IN MODEL HOOK

  model: function(params) {
      return this.store.findRecord('product', params.id );
  },
  
  
// TYPE4 : FETCHING AND SETTING IN MODELHOOKS WITH FILTER
model: function() {
    // return this.store.findAll('project' ,{reload: true});
    return Ember.RSVP.hash({
     projects: this.store.findAll('project' ,{reload: true}).then(function(projects){
          return {
            runningProjects:  projects.filterBy('status', 'started'),
            processingProjects:  projects.filterBy('status', 'created')
        };
     }),
   });
  },

  setupController: function(controller ,model) {

      controller.set('projects',model.projects);
      controller.set('processingProjects',model.projects.processingProjects);
      controller.set('runningProjects',model.projects.runningProjects);

  }
```


###DEVISE AND LOGIN ROUTE
```
  
  ember install ember-simple-auth

```


```
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
```


```
//routes/login.js

import Ember from 'ember';
import UnauthenticatedRouteMixin from 'ember-simple-auth/mixins/unauthenticated-route-mixin';

export default Ember.Route.extend(UnauthenticatedRouteMixin);
```

```
//routes/application.js

import Ember from 'ember';

import ApplicationRouteMixin from 'ember-simple-auth/mixins/application-route-mixin';
export default Ember.Route.extend(ApplicationRouteMixin, {
  });
```

```
//app/authenticators/devise.js

import ENV from '../config/environment';
import DeviseAuthenticator from 'ember-simple-auth/authenticators/devise';

export default DeviseAuthenticator.extend({
  serverTokenEndpoint: ENV.APP.host + '/users/sign_in'
});
```
```
//app/authorizers/devise.js

import DeviseAuthorizer from 'ember-simple-auth/authorizers/devise';

export default DeviseAuthorizer.extend({
  actions: {
    authorize: function(){
      this.get('session').authorize('authorizer:devise', () => {
      });
    }
  }
});
```







###Dashboard devise integration
  
```  
//app/routes/dashboard.js

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
```



###A sample dashboard template
```
//app/templates/dashboard.hbs


<i class="logout icon" {{action "logout"}}> Logout</i>

```
  


###ADAPTER & SERIALIZER
```
//app/config/adapters/application.js

import DS from 'ember-data';
import ENV from '../config/environment';
import DataAdapterMixin from 'ember-simple-auth/mixins/data-adapter-mixin';

export default DS.JSONAPIAdapter.extend(DataAdapterMixin,{
  host: ENV.APP.host,
  authorizer: 'authorizer:devise'
});
```
```
//app/config/serializers/application.js

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
```



### BEST PRACTICE FOR ROUTE HOOKS
```
model: function() {
    return this.store.findAll('product');
  },

  setupController: function(controller ,model) {
        controller.set('products',model);
       controller.set('suppliers', this.store.findAll('supplier'));
       }

```

# ATOM IDE CONFIGURATION

###Linter
```
apm install jshint
```
###AutoIndent Code


```
// put this code to keymap.cson
'atom-text-editor':
  'cmd-alt-l': 'editor:auto-indent'
```


### RAILS RECREATE DATABASE AND MIGRATE 
```

 heroku pg:reset DATABASE_URL
 
 heroku run  rake db:migrate
 
 heroku run rake db:seed

```


## EMBER-RAILS CLOUDINARY FILE UPLOAD 


### EMBER:
```
npm install --save-dev ember-cli-uploader
ember generate ember-cli-uploader
```

Add a field  (like "url") in database and add to models

```
// models file
url: attr('string')
```

```
ember g component file-upload
```
```
//app/components/file-upload.js


import EmberUploader from 'ember-uploader';

export default EmberUploader.FileField.extend({
  url: '',
  filesDidChange: function(files) {

         this.get('on-upload')({
              files: files,

       employee : this.get('employee')
       });
  }
});
```

```
//controller file


import EmberUploader from 'ember-uploader';
import ENV from '../../../config/environment';
session: Ember.inject.service('session'),
imageUploading: false,

actions:{
  uploadProfilePic :function(params){
    var controller = this;


    var authenticated = controller.get('session.data.authenticated');
    let files = params.files,
    employee = params.employee;


    var uploader = EmberUploader.Uploader.extend({
      url: ENV.APP.host + '/employees/'+employee.id,
      type: 'PATCH',
      paramNamespace: 'employee',
      paramName: 'url',
      ajaxSettings: function() {
        var settings = this._super.apply(this, arguments);
        settings.headers = {
          'Authorization':'Token token="'+ authenticated.token +'", email="'+ authenticated.email +'"'
        };
        return settings;
      }
    }).create();


    uploader.on('progress', function() {
      controller.set('imageUploading',true);
    });

    uploader.on('didUpload', function() {
      controller.notifications.addNotification({
        message:  'File uploaded' ,
        type: 'success',
        autoClear: true
      });
      controller.set('imageUploading',false);
    });

    uploader.on('didError', function(jqXHR, textStatus, errorThrown) {
      controller.notifications.addNotification({
        message: 'Sorry something went wrong' ,
        type: 'success',
        autoClear: true
      });
      console.log(jqXHR + textStatus + errorThrown);
      controller.set('imageUploading',false);
    });


    if (!Ember.isEmpty(files)) {
      uploader.upload(files[0]).then(function(){
        controller.get('employee').reload();
      }
    );
  }


},
}
```


### RAILS:

```

// gem file

gem 'carrierwave', github: 'carrierwaveuploader/carrierwave'
gem 'cloudinary'
gem "mini_magick"
```


```
// app/uploaders/employee_uploader.rb

# encoding: utf-8
  class EmployeeUploader < CarrierWave::Uploader::Base

  include Cloudinary::CarrierWave
  include CarrierWave::MiniMagick

  # def store_dir
  #   'public/uploads'
  # end

  version :thumb do
    process resize_to_fit: [200, 300]
  end

end

```


```
//  app/models/employee.rb

mount_uploader :url, EmployeeUploader
attr_accessor :is_thumbnable
```





