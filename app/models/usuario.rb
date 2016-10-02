class Usuario < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  devise :omniauthable, omniauth_providers: [:facebook]

#Mehtod to validate if the user has logged with facebook
  def self.find_or_created_by_omniauth(auth)
    #Find if a user has logged with facebook
    usuario = Usuario.where(provider: auth[:provider], uid: auth[:uid]).first

    unless usuario
#if he hasn't logged with facebook we created
#The fields that we set are the ones in the database
      usuario = Usuario.create(
        nombre: auth[:nombre],
        apellido: auth[:apellido],
        username: auth[:username],
        email: auth[:email],
        uid: auth[:uid],
        provider: auth[:provider],
        #friendly_token generates a radom password
        password: Devise.friendly_token[0,20]
      )
    end
    #returned usuario and that makes the the validation complete
    usuario
  end
end
