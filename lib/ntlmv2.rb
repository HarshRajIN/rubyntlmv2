# vim: set et sw=2 sts=2:

require 'ntlm/util'
require 'ntlm/message'

module NTLMV2

  begin
    Version = File.read(File.dirname(__FILE__) + '/../VERSION').strip
  rescue
    Version = 'unknown'
  end

  def self.negotiate(args = {})
    Message::Negotiate.new(args)
  end

  def self.authenticate(challenge_message, user, domain, password, options = {})
    challenge = Message::Challenge.parse(challenge_message)

    opt = options.merge({
                          :ntlm_v2_session => challenge.has_flag?(:NEGOTIATE_EXTENDED_SECURITY),
                        })
    ntv2_response, lmv2_response = Util.final_ntlm_v2_response(user, password, domain, challenge.challenge, opt)

    Message::Authenticate.new(
      :user        => user,
      :domain      => domain,
      :lm_response => lmv2_response,
      :nt_response => ntv2_response
    )
  end

end # NTLM
