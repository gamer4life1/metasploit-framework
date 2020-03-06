require 'redcarpet'
require 'erb'

module Redcarpet
  module Render
    class MsfMdHTML < Redcarpet::Render::HTML

      def block_code(code, _language)
        code = Regexp.last_match(1) if code =~ %r{^<ruby>(.+)</ruby>}m

        "<pre>" \
          "<code>#{code}</code>" \
        "</pre>"
      end

      def list(content, list_type)
        if list_type == :unordered && content.scan(/<li>/).flatten.length > 15
          %(<p><div id=\"long_list\"><ul>#{content}<ul></div></p>)
        elsif list_type == :unordered
          %(<ul>#{content}</ul>)
        elsif list_type == :ordered
          %(<ol>#{content}</ol>)
        else
          content
        end
      end

      def header(text, header_level)
        %(<h#{header_level}>#{text}</h#{header_level}><hr>)
      end

      def table(header, body)
        %(<table class="kb_table" cellpadding="5" cellspacing="2" border="1">#{header}#{body}</table><br>)
      end

    end
  end
end


module Msf
  module Util
    module DocumentGenerator
      class DocumentNormalizer

        #
        # Markdown templates
        #

        CSS_BASE_PATH                   = 'markdown.css'.freeze
        HTML_TEMPLATE                   = 'html_template.erb'.freeze
        TEMPLATE_PATH                   = 'default_template.erb'.freeze

        #
        # Demo templates
        #

        REMOTE_EXPLOIT_DEMO_TEMPLATE    = 'remote_exploit_demo_template.erb'.freeze
        BES_DEMO_TEMPLATE               = 'bes_demo_template.erb'.freeze
        HTTPSERVER_DEMO_TEMPLATE        = 'httpserver_demo_template.erb'.freeze
        GENERIC_DEMO_TEMPLATE           = 'generic_demo_template.erb'.freeze
        LOCALEXPLOIT_DEMO_TEMPLATE      = 'localexploit_demo_template.erb'.freeze
        POST_DEMO_TEMPLATE              = 'post_demo_template.erb'.freeze
        AUXILIARY_SCANNER_DEMO_TEMPLATE = 'auxiliary_scanner_template.erb'.freeze
        PAYLOAD_DEMO_TEMPLATE           = 'payload_demo_template.erb'.freeze
        EVASION_DEMO_TEMPLATE           = 'evasion_demo_template.erb'.freeze

        # Special messages
        NO_CVE_MESSAGE = %|CVE: [Not available](https://github.com/rapid7/metasploit-framework/wiki/Why-CVE-is-not-available)|.freeze


        # Returns the module document in HTML form.
        #
        # @param items [Hash] Items to be documented.
        # @param kb [String] Additional information to be added in the doc.
        # @return [String] HTML.
        def get_md_content(items, kb)
          @md_template ||= lambda {
            template = ''
            path = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', TEMPLATE_PATH))
            File.open(path, 'rb') { |f| template = f.read }
            return template
          }.call
          md_to_html(ERB.new(@md_template).result(binding), kb)
        end


        private


        # Returns the CSS code for the HTML document.
        #
        # @return [String]
        def load_css
          @css ||= lambda {
            data = ''
            path = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', CSS_BASE_PATH))
            File.open(path, 'rb') { |f| data = f.read }
            return data
          }.call
        end

        # Returns the HTML document.
        #
        # @param md [String] Markdown document.
        # @param kb [String] Additional information to add.
        # @return [String] HTML document.
        def md_to_html(md, kb)
          extensions = {
            escape_html: true
          }

          render_options = {
            fenced_code_blocks: true,
            no_intra_emphasis: true,
            tables: true
          }

          html_renderer = Redcarpet::Render::MsfMdHTML.new(extensions)
          r = Redcarpet::Markdown.new(html_renderer, render_options)
          ERB.new(@html_template ||= lambda {
            html_template = ''
            path = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', HTML_TEMPLATE))
            File.open(path, 'rb') { |f| html_template = f.read }
            return html_template
          }.call).result(binding)
        end

        # Returns the markdown format for pull requests.
        #
        # @param pull_requests [Hash] Pull requests
        # @return [String]
        def normalize_pull_requests(pull_requests)
          if pull_requests.is_a?(PullRequestFinder::Exception)
            error = pull_requests.message
            case error
            when /GITHUB_OAUTH_TOKEN/i
              error << " [See how]("
              error << "https://help.github.com/articles/creating-an-access-token-for-command-line-use/"
              error << ")"
            end
            return error
          end

          formatted_pr = []

          pull_requests.each_pair do |number, pr|
            formatted_pr << "* [##{number} #{pr[:title]}](https://github.com/rapid7/metasploit-framework/pull/#{number})"
          end

          formatted_pr * "\n"
        end

        # Returns the markdown format for module datastore options.
        #
        # @param mod_options [Hash] Datastore options
        # @return [String]
        def normalize_options(mod_options)
          required_options = []

          mod_options.each_pair do |name, props|
            if props.required && props.default.nil?
              required_options << "* #{name} - #{props.desc}"
            end
          end

          required_options * "\n"
        end

        # Returns the markdown format for module description.
        #
        # @param description [String] Module description.
        # @return [String]
        def normalize_description(description)
          Rex::Text.wordwrap(Rex::Text.compress(description))
        end

        # Returns the markdown format for module authors.
        #
        # @param authors [Array, String] Module Authors
        # @return [String]
        def normalize_authors(authors)
          if authors.is_a?(Array)
            authors.collect { |a| "* #{CGI.escapeHTML(a)}" } * "\n"
          else
            authors
          end
        end

        # Returns the markdown format for module targets.
        #
        # @param targets [Array] Module targets.
        # @return [String]
        def normalize_targets(targets)
          targets.collect { |c| "* #{c.name}" } * "\n"
        end

        # Returns the markdown format for module references.
        #
        # @param refs [Array] Module references.
        # @return [String]
        def normalize_references(refs)
          normalized = ''
          cve_collection = refs.select { |r| r.ctx_id.match(/^cve$/i) }
          if cve_collection.empty?
            normalized << "* #{NO_CVE_MESSAGE}\n"
          end

          refs.each do |ref|
            case ref.ctx_id
            when 'MSB'
              normalized << "* [#{ref.ctx_val}](#{ref.site})"
            when 'URL'
              normalized << "* [#{ref.site}](#{ref.site})"
            when 'US-CERT-VU'
              normalized << "* [VU##{ref.ctx_val}](#{ref.site})"
            when 'CVE', 'cve'
              if !cve_collection.empty? && ref.ctx_val.blank?
                normalized << "* #{NO_CVE_MESSAGE}"
              end
            else
              normalized << "* [#{ref.ctx_id}-#{ref.ctx_val}](#{ref.site})"
            end
            normalized << "\n"
          end
          normalized
        end

        # Returns the markdown format for module platforms.
        #
        # @param platforms [Array, String] Module platforms.
        # @return [String]
        def normalize_platforms(platforms)
          if platforms.is_a?(Array)
            platforms.collect { |p| "* #{p}" } * "\n"
          else
            platforms
          end
        end

        # Returns the markdown format for module rank.
        #
        # @param rank [String] Module rank.
        # @return [String]
        def normalize_rank(rank)
          "[#{Msf::RankingName[rank].capitalize}](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking)"
        end

        # Returns the markdown format for module side effects.
        #
        # @param side_effects [Array<String>] Module effects.
        # @return [String]
        def normalize_side_effects(side_effects)
          md_side_effects = side_effects.collect { |s| "* #{s}\n" }.join
          md_side_effects.empty? ? 'N/A' : md_side_effects
        end

        # Returns the markdown format for module reliability.
        #
        # @param reliability [Array<String>] Module reliability.
        # @return [String]
        def normalize_reliability(reliability)
          md_reliability = reliability.collect { |r| "* #{r}\n" }.join
          md_reliability.empty? ? 'N/A' : md_reliability
        end

        def normalize_stability(stability)
          md_stability = stability.collect { |s| "* #{s}\n" }.join
          md_stability.empty? ? 'N/A' : md_stability
        end

        # Returns a parsed demo ERB template.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @param path [String] Template path.
        # @return [String]
        def load_demo_template(mod, path)
          data = ''
          path = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', path))
          File.open(path, 'rb') { |f| data = f.read }
          ERB.new(data).result(binding)
        end

        # Returns whether the module is a remote exploit or not.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @return [TrueClass] Module is a remote exploit.
        # @return [FalseClass] Module is not really a remote exploit.
        def is_remote_exploit?(mod)
          # It's actually a little tricky to determine this, so we'll try to be as
          # specific as possible. Rather have false negatives than false positives,
          # because the worst case would be using the generic demo template.
          mod.type == 'exploit' && # Must be an exploit
            mod.is_a?(Msf::Exploit::Remote) &&             # Should always have this
            !mod.is_a?(Msf::Exploit::FILEFORMAT) &&        # Definitely not a file format
            !mod.is_a?(Msf::Exploit::Remote::TcpServer) && # If there is a server mixin, things might get complicated
            mod.options['DisablePayloadHandler'] # Must allow this option
        end

        # Returns a demo template suitable for the module. Currently supported templates:
        # BrowserExploitServer modules, HttpServer modules, local exploit modules, post
        # modules, payloads, auxiliary scanner modules.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @return [String]
        def normalize_demo_output(mod)
          if mod.is_a?(Msf::Exploit::Remote::BrowserExploitServer) && mod.shortname != 'browser_autopwn2'
            load_demo_template(mod, BES_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Exploit::Remote::HttpServer)
            load_demo_template(mod, HTTPSERVER_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Exploit::Local)
            load_demo_template(mod, LOCALEXPLOIT_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Post)
            load_demo_template(mod, POST_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Payload)
            load_demo_template(mod, PAYLOAD_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Auxiliary::Scanner)
            load_demo_template(mod, AUXILIARY_SCANNER_DEMO_TEMPLATE)
          elsif is_remote_exploit?(mod)
            load_demo_template(mod, REMOTE_EXPLOIT_DEMO_TEMPLATE)
          elsif mod.is_a?(Msf::Evasion)
            load_demo_template(mod, EVASION_DEMO_TEMPLATE)
          else
            load_demo_template(mod, GENERIC_DEMO_TEMPLATE)
          end
        end

      end
    end
  end
end
