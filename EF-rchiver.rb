$LOAD_PATH << '.'
require 'datbot'
#https://github.com/MusikAnimal/MusikBot/blob/master/tasks/perm_clerk.rb
#Apache License 2.0, see directory
module EFrchiver
  def self.run
    @db = DatBot::Session.new(inspect)
    
    @denied_cache = {}
    @archive_changes = {}
    @errors = {}
    
    
    @db.config[:pages].keys.each do |permission|
      @permission = permission.to_s
      @edit_summaries = []
      @headers_removed = {}
      @users_count = 0

      begin
        @flag_as_ran = false
        process_permission

        if @flag_as_ran
          @total_user_count += @users_count
          run_status[@permission] = @db.now.to_s
        end
      rescue => e
        @db.report_error("Failed to process #{permission}", e)
        @errors[@permission] = @errors[@permission].to_a << {
          group: 'fatal',
          message: 'Failed for unknown reasons. Check the [[User:DatBot/Error log|error log]] ' \
            'and contact the [[User talk:DatGuy|bot operator]] if you are unable to resolve the issue.'
        }
      end
    end

    archive_requests if @archive_changes.any?

    generate_report

    @db.local_storage(run_status)

    info("#{'~' * 25} Task complete #{'~' * 25}")
  rescue => e
    @db.report_error('Fatal error', e)
  end
  rescue MediaWiki::APIError => e
    if throttle > 3
      @db.report_error('Edit throttle hit', e)
    elsif e.code.to_s == 'editconflict'
      process_permission(throttle + 1)
    else
      raise
    end
  end
  def self.process_section(section)
    
    @section = section
    @request_changes = []
    username = @section.scan(/{{(?:template\:)?rfplinks\|1=(.*?)}}/i).flatten[0]
    return SPLIT_KEY + @section unless username
    username[0] = username[0].capitalize
    username.strip!
    @username = username.descore

    info("Checking section for User:#{@username}...")

    timestamps = @section.scan(/(?<!\<!-- dbdate --\> )\b\d\d:\d\d, \d+ \w+ \d{4} \(UTC\)/)
    @newest_timestamp = @db.parse_date(timestamps.min { |a, b| @db.parse_date(b) <=> @db.parse_date(a) })
    @request_timestamp = @db.parse_date(timestamps.min { |a, b| @db.parse_date(a) <=> @db.parse_date(b) })

    overriden_resolution = if @section =~ %r{\{\{User:DatBot/override\|d\}\}}
                             'done'
                           elsif @section =~ /\{\{User:DatBot\/override\|nd\}\}/i
                             'notdone'
                           else
                             false
                           end

    info('Resolution override found') if overriden_resolution

    done_regex = @db.config[:archive_config][:done]
    notdone_regex = @db.config[:archive_config][:notdone]
    revoked_regex = @db.config[:archive_config][:revoked]

    resolution = if overriden_resolution
                   overriden_resolution
                 elsif @section =~ /(?:#{revoked_regex})/i
                   'revoked'
                 elsif @section =~ /(?:#{done_regex})/i
                   'done'
                 elsif @section =~ /(?:#{notdone_regex})/i
                   'notdone'
                 else
                   false
                 end

    resolution_timestamp = @db.parse_date(
      @section.scan(/(?:#{@db.config[:archive_config][resolution.to_sym]}).*(\d\d:\d\d, \d+ \w+ \d{4} \(UTC\))/i).flatten.drop(1).last
    ) if resolution

    # use newest timestamp when forcing resolution and no resolution template exists
    if resolution_timestamp.nil? && overriden_resolution
      resolution_timestamp = @newest_timestamp
    end

    @num_open_requests += 1 unless resolution

    # archiving has precedence; e.g. if we are archiving, we don't do anything else for this section
    return if archiving(resolution, overriden_resolution, resolution_timestamp)

    # determine if there's any else to be done
    if resolution
      info("  #{@username}'s request already responded to")
      @new_wikitext << SPLIT_KEY + @section
      return
    end

    @open_timestamps << timestamps.min { |a, b| @db.parse_date(a) <=> @db.parse_date(b) }
    @should_update_prereq_data = should_update_prereq_data

    if @section.match(/{{comment\|Automated comment}}.*MusikBot/) && !@should_update_prereq_data
      info("DatBot has already commented on #{username}'s request and no prerequisite data to update")
      @new_wikitext << SPLIT_KEY + @section
      return
    end

    # these tasks have already been ran if we're just updating prereq data
    unless @should_update_prereq_data
      # autoformat first, especially the case for Confirmed where they have a malformed report and are already autoconfirmed
      autoformat
      if autorespond
        @num_open_requests -= 1
        return queue_changes
      end
      fetch_declined
      check_revoked
    end
    prerequisites
    queue_changes
  end

  def self.archive_requests
    num_requests = @archive_changes.values.flatten.length

    info("***** Archiving #{num_requests} requests *****")

    @archive_changes.keys.each do |key|
      page_to_edit = "Wikipedia:Requests for permissions/#{key}"
      month_name = key.scan(/\/(\w+)/).flatten[0]
      year = key.scan(/\d{4}/).flatten[0]

      page_wikitext = @db.get(page_to_edit) || ''
      new_page = page_wikitext.blank?

      edit_summary = "Archiving #{@archive_changes[key].length} request#{'s' if @archive_changes[key].length > 1}:"

      # ensure there's a newline at the end
      page_wikitext = page_wikitext.chomp('') + "\n"

      # convert sections as a hash of format {"Month day" => "content"}
      sections = Hash[*page_wikitext.split(/\=\=\s*(\w+ \d+)\s*\=\=/).drop(1).flatten(1)]

      @archive_changes[key].each do |request|
        edit_summary += " #{request[:username]} (#{request[:permission].downcase});"
        archive_page_name = "Wikipedia:Requests for permissions/#{request[:permission]}"
        link_markup = "*{{Usercheck-short|#{request[:username]}}} [[#{archive_page_name}]] " \
          "<sup>[http://en.wikipedia.org/wiki/Special:PermaLink/#{request[:revision_id]}#User:#{request[:username].score} link]</sup>"

        # add link_markup to section
        section_key = "#{month_name} #{request[:date].day}"
        sections[section_key] = sections[section_key].to_s.gsub(/^\n|\n$/, '') + "\n" + link_markup + "\n"
      end
      edit_summary.chomp!(';')

      # construct back to single wikitext string, sorted by day
      new_wikitext = ''
      sorted_keys = sections.keys.sort_by { |k| k.scan(/\d+/)[0].to_i }
      sorted_keys.each do |sort_key|
        new_wikitext += "\n== " + sort_key + " ==\n" + sections[sort_key].gsub(/^\n/, '')
      end

      # we're done archiving for this month

      # first see if it's a new page and if so add it to the log page
      if new_page
        log_page_name = "Wikipedia:Requests for permissions/#{key.scan(/(.*)\//).flatten[0]}"
        info("  Adding new page [[#{page_to_edit}]] to log [[#{log_page_name}]]")

        log_page = @db.get(log_page_name)

        # convert to {"year" => "requests"}
        year_sections = Hash[*log_page.split(/\=\=\=\s*(\d{4})\s*\=\=\=/).drop(1)]
        year_sections[year] = "\n*[[#{page_to_edit}]]" + year_sections[year].to_s

        log_page_wikitext = ''
        year_sections.sort { |a, b| b <=> a }.to_h.keys.each do |year_section_key|
          log_page_wikitext += "\n=== " + year_section_key + " ===\n" + year_sections[year_section_key].gsub(/^\n/, '')
        end

        info("    Attempting to write to page [[#{log_page_name}]]")
        log_page_wikitext = log_page.split('===')[0] + log_page_wikitext

        @db.edit(log_page_name,
          content: log_page_wikitext,
          summary: "Adding entry for [[#{page_to_edit}]]"
        )
      end

      info("  Attempting to write to page [[#{page_to_edit}]]")
      @db.edit(page_to_edit,
        content: new_wikitext,
        summary: edit_summary
      )
    end
  end
  def self.archiving(resolution, overriden_resolution, resolution_timestamp)
    return false unless @db.config[:run][:archive] && resolution.present?
    should_archive_now = @section.match(/\{\{User:DatBot\/archivenow\}\}/)

    if resolution_timestamp.nil?
      record_error(
        group: 'archive',
        message: "User:#{@username} - Resolution template not dated",
        log_message: "    User:#{@username}: Resolution template not dated"
      )
      return true
    end

    # not time to archive
    unless should_archive_now || @newest_timestamp + Rational(@db.config[:archive_config][:offset].to_i, 24) < @db.now
      return false
    end

    if should_archive_now
      info('  Found request for immediate archiving')
    else
      info('  Time to archive!')
    end

    # if we're archiving as done, check if they have the said permission and act accordingly (skip if overriding resolution)
    if resolution == 'done' && !overriden_resolution && !api_relevant_permission
      if @section.include?('<!-- dbNoPerm -->')
        warn("    MusikBot already reported that #{@username} does not have the permission #{@permission}")
        @new_wikitext << SPLIT_KEY + @section
      else
        @request_changes << {
          type: :noSaidPermission,
          permission: @permission.downcase
        }
        @edit_summaries << :noSaidPermission

        queue_changes

        message = if @permission == 'AutoWikiBrowser'
                    "has not been added to the [[#{AWB_CHECKPAGE}|check page]]"
                  else
                    "does not have the permission #{@permission}"
                  end

        record_error(
          group: 'archive',
          message: "User:#{@username} #{message}. " \
            'Use <code><nowiki>{{subst:User:DatBot/override|d}}</nowiki></code> to archive as approved or ' \
            '<code><nowiki>{{subst:User:DatBot/override|nd}}</nowiki></code> to archive as declined',
          log_message: "    #{@username} #{message}"
        )
      end

      return true
    elsif resolution == 'revoked' && !overriden_resolution && api_relevant_permission
      if @section.include?('<!-- dbHasPerm -->')
        warn("    MusikBot already reported that #{@username} still has the permission #{@permission}")
        @new_wikitext << SPLIT_KEY + @section
      else
        @request_changes << {
          type: :saidPermission,
          permission: @permission.downcase
        }
        @edit_summaries << :saidPermission

        queue_changes

        message = if @permission == 'AutoWikiBrowser'
                    "has not been added to the [[#{AWB_CHECKPAGE}|check page]]"
                  else
                    "does not have the permission #{@permission}"
                  end

        record_error(
          group: 'archive',
          message: "User:#{@username} #{message}. " \
            'Use <code><nowiki>{{subst:User:DatBot/override|d}}</nowiki></code> to archive as approved or ' \
            '<code><nowiki>{{subst:User:DatBot/override|nd}}</nowiki></code> to archive as declined',
          log_message: "    #{@username} #{message}"
        )
      end

      return true
    end

    resolution_page_name = resolution == 'done' || resolution == 'revoked' ? 'Approved' : 'Denied'
    info("    archiving as #{resolution_page_name.upcase}")
    archive_key = "#{resolution_page_name}/#{Date::MONTHNAMES[resolution_timestamp.month]} #{resolution_timestamp.year}"
    archive_set = @archive_changes[archive_key].to_a << {
      username: @username,
      permission: @permission,
      revision_id: @revision_id,
      date: resolution_timestamp
    }
    @archive_changes[archive_key] = archive_set

    @users_count += 1
    @edit_summaries << "archive#{resolution_page_name}".to_sym

    true
  end
  def self.generate_report
    errors_digest = Digest::MD5.hexdigest(@errors.values.join)
    expired = @total_user_count > 0 && @db.parse_date(run_status['report']) < @db.now - Rational(6, 24)
    return unless run_status['report_errors'] != errors_digest || expired

    if @errors.keys.any?
      num_errors = @errors.values.flatten.length
      content = '{{hidden|style=display:inline-block;background:transparent|headerstyle=padding-right:3.5em|header=' \
        "<span style='color:red;font-weight:bold'>#{num_errors} error#{'s' if num_errors > 1} as of ~~~~~</span>|content="
      @errors.keys.each do |permission_group|
        content += "\n;[[Wikipedia:Requests for permissions/#{permission_group}|#{permission_group}]]\n"
        @errors[permission_group].each do |error|
          group = error[:group] == 'fatal' ? 'FATAL' : error[:group].capitalize
          content += "* '''#{group}''': #{error[:message]}\n"
        end
      end
      content += '}}'
    else
      content = "<span style='color:green; font-weight:bold'>No errors!</span> Report generated at ~~~~~"
    end

    run_status['report'] = @db.now.to_s
    run_status['report_errors'] = errors_digest

    info('Updating report...')
    @db.edit('User:DatBot/PermClerk/Report',
      content: content,
      summary: 'Updating [[User:DatBot/PermClerk|PermClerk]] report'
    )
  end
  def self.perm_edit_summary
    summaries = []

    # get approved/denied counts
    approved = @edit_summaries.count(:archiveApproved)
    denied = @edit_summaries.count(:archiveDenied)
    if approved + denied > 0
      archive_msg = []
      archive_msg << "#{approved} approved" if approved > 0
      archive_msg << "#{denied} denied" if denied > 0
      archive_msg = archive_msg.join(', ')
      summaries << "archiving (#{archive_msg})"
    end

    plural = @users_count > 1

    summaries << "marked request#{'s' if plural} as already done" if @edit_summaries.include?(:autorespond)
    summaries << "repaired malformed request#{'s' if plural}" if @edit_summaries.include?(:autoformat)
    summaries << 'prerequisite data updated' if @edit_summaries.include?(:prerequisitesUpdated)
    summaries << 'unmet prerequisites' if @edit_summaries.include?(:prerequisites)
    summaries << 'found previously declined requests' if @edit_summaries.include?(:fetchdeclined)
    summaries << 'found previous revocations' if @edit_summaries.include?(:checkrevoked)
    summaries << 'unable to archive one or more requests' if @edit_summaries.include?(:noSaidPermission) || @edit_summaries.include?(:saidPermission)
    summaries << '{{WP:PERM/Backlog}}' if @edit_summaries.include?(:backlog)
    summaries << '{{WP:PERM/Backlog|none}}' if @edit_summaries.include?(:no_backlog)

    request_count_msg = if @num_open_requests > 0
                          "#{@num_open_requests} open request#{'s' if @num_open_requests > 1} remaining"
                        else
                          '0 open requests remaining'
                        end

    "Bot clerking#{" on #{@users_count} requests" if plural}: #{summaries.join(', ')} (#{request_count_msg})"
  end

  # Config-related
  def self.run_status
    @run_status ||= @mb.local_storage
  end

  def self.prereqs
    @mb.config[:run][:prerequisites] ? @mb.config[:prerequisites_config][@permission.to_sym] : nil
  end

  # API-related
  def self.api_relevant_permission
    info("  checking if #{@username} has permission #{@permission}")
    return @permission if sysop?

    if @permission == 'AutoWikiBrowser'
      awb_checkpage_content =~ /\n\*\s*#{Regexp.escape(@username)}\s*\n/ ? 'AutoWikiBrowser' : nil
    else
      get_user_info(@username)[:userGroups].grep(/#{@mb.config[:pages][@permission.to_sym]}/).first
    end
  end
    def self.page_props(page)
    page_obj = @mb.get_page_props(page, full_response: true)
    @revision_id = page_obj.attributes['lastrevid']
    @last_edit = @mb.parse_date(page_obj.elements['revisions'][0].attributes['timestamp'])
    page_obj.elements['revisions/rev'].text
  rescue
    record_error(
      group: 'fatal',
      message: "The page [[#{page}]] does not exist!"
    )
    nil
  end

  def self.record_error(opts)
    error_set = opts[:error_set] || @permission
    @errors[error_set] = @errors[error_set].to_a << {
      group: opts[:group],
      message: opts[:message]
    }
    error(opts[:log_message])
  end

  def self.info(msg); log("#{@permission.upcase} : #{msg}"); end
  def self.warn(msg); log("#{@permission.upcase} | WARN : #{msg}"); end
  def self.error(msg); log("#{@permission.upcase} | ERROR : #{msg}"); end
  def self.log(message); puts(@mb.now.strftime("%e %b %H:%M:%S | #{message}")); end
end

EFrchiver.run
