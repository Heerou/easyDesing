module ApplicationHelper
  def get_email_ouath
    if session[:omniauth_data]
      session[:omniauth_data] [:email]
    else
      ""
  end
end
