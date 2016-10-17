class Sanitize
  # Helper for sanitizing user input

  def self.bool(crap)
    return true if ( (crap == true) or (crap == 'true') or (crap == 'on') or (crap == 't') )
    return false
  end

  def self.alnum(crap)
    # Allow only alphanumeric characters, strip everything else
    return nil if ! ( crap.is_a?(String) or crap.is_a?(Integer) )
    crap = crap.to_s unless crap.is_a?(String)
    return crap.gsub(/[^a-z0-9]+/i, '')
  end

  def self.alnumsp(crap)
    # Allow only alphanumeric characters and space, strip everything else
    return nil if ! crap.is_a?(String)
    return crap.gsub(/[^a-z0-9]\ +/i, '')
  end

  def self.alnumspp(crap)
    # Allow alphanumeric characters, space, minus - , undescore _, dot ., colon :
    return nil if ! crap.is_a?(String)
    rez = crap.gsub(/[^a-z0-9]*-_\.:\ +/i, '')
    return rez
  end

  def self.intnum(crap, min=0, max=65535)
    return nil if ! ( crap.is_a?(String) or crap.is_a?(Integer) or crap.is_a?(Fixnum) )
    begin
      return crap.to_i
    end
  end

  def self.filename(crap)
    return nil if ! crap.is_a?(String)
    rez = crap.gsub(/[\x00\\:\*\?\"<>\|]/, '')
    return rez
  end

  def self.filepath(crap)
    return nil if ! crap.is_a?(String)
    rez = crap.gsub(/[\x00\/\\:\*\?\"<>\|]/, '')
    return rez
  end

  def self.ldap_dn(crap)
    return nil if ! crap.is_a?(String)
    rez = crap.gsub(/[^a-z0-9]*-_,=\.:;\ +/i, '')
    return rez
  end

  def self.ipaddr(crap)
    return nil if ! crap.match /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/
    begin
      return crap
    end
  end

  def self.timezone(crap)
    return nil if crap.nil?
    return nil if ! crap.match /[a-z0-9]+\/*/i
    begin
      return crap
    end
  end

  def self.json(crap)
    # Returns parsed JSON or nil if it's not json
    # @param [String] crap
    # @return [Hash] parsed JSON
    begin
      return JSON.parse(crap).to_json
    rescue Exception => e
      $log.error "action: Sanitize.json, result: failed, reason: #{e}"
      return nil
    end
  end

  def self.alertime(time)
    return time if Validator.alertime(time)
  end
end
