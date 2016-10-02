class OmniauthCallbacksController < ApplicationController
#Method for facebook login
  def facebook
    #Has with the user info
    auth = request.env["omniauth.auth"]
    #raise userAuthInfo.to_yaml
#hashes in ruby, it's like an AJAX
    data = {
      nombre: auth.info.first_name,
      apellido: auth.info.last_name,
      username: auth.info.nickanme,
      email: auth.info.email,
      provider: auth.provider,
      uid: auth.uid
    }

    @usuario = Usuario.find_or_created_by_omniauth(data)

#.persisted? return true if is true
    if @usuario.persisted?
      sign_in_and_redirect @usuario, event: :authentication
    else
      session[:omniauth_errors] = @usuario.errors.full_messages.to_sentence unless @usuario.save

      session[:omniauthable_data] = data

#if the user is not created it redirects to the registration page
      redirect_to_new_usuario_registration_url
    end
  end
end
