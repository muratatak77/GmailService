class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  rescue_from Exception, with: :error_occurred

  def error_occurred(exception)
    if (exception.to_s.include? 'Authorization') || (exception.to_s.include? 'invalid_grant')
      redirect_to controller: :oauth, action: :index
    else
      puts "GETTING ANOTHER ERROR : #{exception.message}"
    end
  end
end
