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
#
# Reads through `Params.str` / `Params.provided` so the body stays
# concretely typed (same posture as pagination's `?page=` read).
require_relative "../params"

module ActionController
  module InvisibleCaptcha
    HONEYPOTS = %w[subtitle url website email_confirm].freeze

    def self.spam?(params)
      HONEYPOTS.any? do |name|
        Params.provided(params, name) && !Params.str(params, name, "").empty?
      end
    end
  end
end
