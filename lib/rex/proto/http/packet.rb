# -*- coding: binary -*-

require 'rex/proto/http'

module Rex
  module Proto
    module Http
      DefaultProtocol = '1.1'.freeze

      ###
      #
      # This class represents an HTTP packet.
      #
      ###
      class Packet

        #
        # Parser processing codes
        #
        module ParseCode
          Completed = 1
          Partial   = 2
          Error     = 3
        end

        #
        # Parser states
        #
        module ParseState
          ProcessingHeader = 1
          ProcessingBody   = 2
          Completed        = 3
        end

        require 'rex/proto/http/packet/header'

        #
        # Initializes an instance of an HTTP packet.
        #
        def initialize
          self.headers = Header.new
          self.auto_cl = true

          reset
        end

        #
        # Return the associated header value, if any.
        #
        def [](key)
          if headers.include?(key)
            return headers[key]
          end

          headers.each_pair do |k, v|
            if (k.downcase == key.downcase)
              return v
            end
          end

          return nil
        end

        #
        # Set the associated header value.
        #
        def []=(key, value)
          headers[key] = value
        end

        #
        # Parses the supplied buffer.  Returns one of the two parser processing
        # codes (Completed, Partial, or Error).
        #
        def parse(buf)

          # Append the incoming buffer to the buffer queue.
          self.bufq += buf.to_s

          begin
            # Process the header
            if (state == ParseState::ProcessingHeader)
              parse_header
            end

            # Continue on to the body if the header was processed
            if (state == ParseState::ProcessingBody)
              # Chunked encoding sets the parsing state on its own
              if ((body_bytes_left == 0) && !transfer_chunked)
                self.state = ParseState::Completed
              else
                parse_body
              end
            end
          rescue StandardError
            # XXX: BUG: This rescue might be a problem because it will swallow TimeoutError
            self.error = $ERROR_INFO
            return ParseCode::Error
          end

          # Return completed or partial to the parsing status to the caller
          (state == ParseState::Completed) ? ParseCode::Completed : ParseCode::Partial
        end

        #
        # Reset the parsing state and buffers.
        #
        def reset
          self.state = ParseState::ProcessingHeader
          self.transfer_chunked = false
          self.inside_chunk     = false
          headers.reset
          self.bufq  = ''
          self.body  = ''
        end

        #
        # Reset the parsing state but leave the buffers.
        #
        def reset_except_queue
          self.state = ParseState::ProcessingHeader
          self.transfer_chunked = false
          self.inside_chunk     = false
          headers.reset
          self.body = ''
        end

        #
        # Returns whether or not parsing has completed.
        #
        def completed?

          return true if state == ParseState::Completed

          # If the parser state is processing the body and there are an
          # undetermined number of bytes left to read, we just need to say that
          # things are completed as it's hard to tell whether or not they really
          # are.
          if ((state == ParseState::ProcessingBody) && (body_bytes_left < 0))
            return true
          end

          false
        end

        #
        # Build a 'Transfer-Encoding: chunked' payload with random chunk sizes
        #
        def chunk(str, min_size = 1, max_size = 1000)
          chunked = ''

          # min chunk size is 1 byte
          if (min_size < 1); min_size = 1; end

          # don't be dumb
          if (max_size < min_size); max_size = min_size; end

          until str.empty?
            chunk = str.slice!(0, rand(max_size - min_size) + min_size)
            chunked += format("%x", chunk.size) + "\r\n" + chunk + "\r\n"
          end
          chunked += "0\r\n\r\n"
        end

        #
        # Outputs a readable string of the packet for terminal output
        #
        def to_terminal_output(headers_only: false)
          output_packet(true, headers_only: headers_only)
        end

        #
        # Converts the packet to a string.
        #
        def to_s(headers_only: false)
          output_packet(false, headers_only: headers_only)
        end

        #
        # Converts the packet to a string.
        # If ignore_chunk is set the chunked encoding is omitted (for pretty print)
        #
        def output_packet(ignore_chunk = false, headers_only: false)
          content = body.to_s.dup

          # Update the content length field in the header with the body length.
          if content
            if !compress.nil?
              case compress
              when 'gzip'
                headers['Content-Encoding'] = 'gzip'
                content = Rex::Text.gzip(content)
              when 'deflate'
                headers['Content-Encoding'] = 'deflate'
                content = Rex::Text.zlib_deflate(content)
              when 'none'
                # this one is fine...
                # when 'compress'
              else
                raise 'Invalid Content-Encoding'
              end
            end

            unless ignore_chunk
              if auto_cl && transfer_chunked
                raise "'Content-Length' and 'Transfer-Encoding: chunked' are incompatible"
              end

              if auto_cl
                headers['Content-Length'] = content.length
              elsif transfer_chunked
                if proto != '1.1'
                  raise 'Chunked encoding is only available via 1.1'
                end

                headers['Transfer-Encoding'] = 'chunked'
                content = chunk(content, chunk_min_size, chunk_max_size)
              end
            end
          end

          str  = headers.to_s(cmd_string)
          str += content || '' unless headers_only

          str
        end

        #
        # Converts the packet from a string.
        #
        def from_s(str)
          reset
          parse(str)
        end

        #
        # Returns the command string, such as:
        #
        # HTTP/1.0 200 OK for a response
        #
        # or
        #
        # GET /foo HTTP/1.0 for a request
        #
        def cmd_string
          headers.cmd_string
        end

        attr_accessor :headers
        attr_accessor :error
        attr_accessor :state
        attr_accessor :bufq
        attr_accessor :body
        attr_accessor :auto_cl
        attr_accessor :max_data
        attr_accessor :transfer_chunked
        attr_accessor :compress
        attr_reader   :incomplete

        attr_accessor :chunk_min_size
        attr_accessor :chunk_max_size

        protected

        attr_writer   :incomplete
        attr_accessor :body_bytes_left
        attr_accessor :inside_chunk
        attr_accessor :keepalive

        ##
        #
        # Overridable methods
        #
        ##

        #
        # Allows derived classes to split apart the command string.
        #
        def update_cmd_parts(str); end

        ##
        #
        # Parsing
        #
        ##

        def parse_header

          head, data = self.bufq.split(/\r?\n\r?\n/, 2)

          return if !data

          headers.from_s(head)
          self.bufq = data || ""

          # Set the content-length to -1 as a placeholder (read until EOF)
          self.body_bytes_left = -1

          # Extract the content length if it was specified
          if headers['Content-Length']
            self.body_bytes_left = headers['Content-Length'].to_i
          end

          # Look for a chunked transfer header
          if (headers['Transfer-Encoding'].to_s.downcase == 'chunked')
            self.transfer_chunked = true
            self.auto_cl = false
          end

          # Determine how to handle data when there is no length header
          if (body_bytes_left == -1)
            if !transfer_chunked
              if headers['Connection'].to_s.downcase.include?('keep-alive')
                # If we are using keep-alive, but have no content-length and
                # no chunked transfer header, pretend this is the entire
                # buffer and call it done
                self.body_bytes_left = self.bufq.length
              elsif (!headers['Content-Length'] && (self.class == Rex::Proto::Http::Request))
                # RFC 2616 says: "The presence of a message-body in a request
                # is signaled by the inclusion of a Content-Length or
                # Transfer-Encoding header field in the request's
                # message-headers."
                #
                # So if we haven't seen either a Content-Length or a
                # Transfer-Encoding header, there shouldn't be a message body.
                self.body_bytes_left = 0
                # else
                # Otherwise we need to keep reading until EOF
              end
            end
          end

          # Throw an error if we didnt parse the header properly
          if !headers.cmd_string
            raise RuntimeError, "Invalid command string", caller
          end

          # Move the state into body processing
          self.state = ParseState::ProcessingBody

          # Allow derived classes to update the parts of the command string
          update_cmd_parts(headers.cmd_string)
        end

        #
        # Parses the body portion of the request.
        #
        def parse_body
          # Just return if the buffer is empty
          if self.bufq.empty?
            return
          end

          # Handle chunked transfer-encoding responses
          if (transfer_chunked && (inside_chunk != 1) && self.bufq.length)

            # Remove any leading newlines or spaces
            self.bufq.lstrip!

            # If we didn't get a newline, then this might not be the full
            # length, go back and get more.
            # e.g.
            #  first packet: "200"
            #  second packet: "0\r\n\r\n<html>..."
            if !bufq.index("\n")
              return
            end

            # Extract the actual hexadecimal length value
            clen = self.bufq.slice!(/^[a-fA-F0-9]+\r?\n/)

            clen&.rstrip!

            # if we happen to fall upon the end of the buffer for the next chunk len and have no data left, go get some more...
            if clen.nil? && self.bufq.empty?
              return
            end

            # Invalid chunk length, exit out early
            if clen.nil?
              self.state = ParseState::Completed
              return
            end

            self.body_bytes_left = clen.to_i(16)

            if (body_bytes_left == 0)
              self.bufq.sub!(/^\r?\n/s, '')
              self.state = ParseState::Completed
              check_100
              return
            end

            self.inside_chunk = 1
          end

          # If there are bytes remaining, slice as many as we can and append them
          # to our body state.
          if (body_bytes_left > 0)
            part = self.bufq.slice!(0, body_bytes_left)
            self.body += part
            self.body_bytes_left -= part.length
          # Otherwise, just read it all.
          else
            self.body += self.bufq
            self.bufq  = ''
          end

          # Finish this chunk and move on to the next one
          if (transfer_chunked && (self.body_bytes_left == 0))
            self.inside_chunk = 0
            parse_body
            return
          end

          # If there are no more bytes left, then parsing has completed and we're
          # ready to go.
          if (!transfer_chunked && (self.body_bytes_left == 0))
            self.state = ParseState::Completed
            check_100
            return
          end
        end

        # Override this as needed
        def check_100; end

      end
      end
  end
end
