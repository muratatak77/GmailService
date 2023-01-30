module DateTimeRanges
  def last_week_range
    start_of_week = self - 1.week
    start_of_week.beginning_of_week..start_of_week.end_of_week
  end

  def last_7_days
    self.beginning_of_day - 1.week .. self.end_of_day
  end

  def days_ago(day)
    day = self.beginning_of_day - day.days
    day..day.end_of_day
  end

  def last_weekday(wday)
    raise "invalid weekday:#{wday}" unless (0..6).include?(wday)
    last_week = self - 1.week
    day = last_week.beginning_of_week + wday.days
    day.beginning_of_day..day.end_of_day
  end

  def last_15_minutes
    now = self
    (now-15.minutes)..now
  end

  def today
    now = self
    now.beginning_of_day..now.end_of_day
  end
end

class Object
  include DateTimeRanges

  def to_imap_date
    Date.parse(to_s).strftime("%d-%b-%Y")
  end

  def to_imap_internal_date
    str = to_s.split(" ")
    str.delete_at(0)
    ([to_s.to_imap_date] + str).join(" ")
  end

  # convert date/time to same wall time, but in different timezone
  def swap_time_zone(to_tz)
    from_utc_offset = utc_offset
    to_utc_offset = in_time_zone(to_tz).utc_offset
    delta = from_utc_offset - to_utc_offset
    if delta <= -12.hours
      self + (24.hours + delta)
    elsif delta >= 12.hours
      self - (24.hours - delta)
    else
      self + delta
    end
  end

  SetterCache = {}

  def self.from_hash(h)
    new.tap do |s|
      h.each_pair do |k, v|
        setter = SetterCache.fetch(k) do |key|
          SetterCache[key] = "#{k.to_sym}="
        end
        s.send(setter, v)
      end
    end
  end
end
