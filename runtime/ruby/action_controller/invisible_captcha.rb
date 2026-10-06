# Spam gate behind `invisible_captcha` (the invisible_captcha gem).
#
# The lowering synthesizes:
#
#   before_action :detect_invisible_captcha_spam, only: …
#   def detect_invisible_captcha_spam
#     head :ok if ActionController::InvisibleCaptcha.spam?(params)
#   end
#
# `spam?` is true when a honeypot field is filled. The gem's default
# honeypot names rotate; we recognize the common published defaults.
# Timestamp / spinner / custom `on_spam` callbacks are not modeled —
# unsupported kwargs leave the class-body macro as a survey gap.
module ActionController
  module InvisibleCaptcha
    HONEYPOTS = %w[subtitle url website email_confirm].freeze

    def self.spam?(params)
      return false if params.nil?
      HONEYPOTS.any? do |name|
        value = params[name] || params[name.to_sym]
        !(value.nil? || value.to_s.empty?)
      end
    end
  end
end
