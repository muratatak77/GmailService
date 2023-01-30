class Module

  def constant_values
    constants.map {|c| const_get(c)}
  end

  # This method was deprecated in Rails 5.0.x and was removed in Rails 5.1.  We have
  # opted to keep this method.  This is the code from 5.0.7.2 version of Rails where
  # the deprecation warning has been remove.  It was deprecated in favor of using the
  # Ruby 2.0+ prepend method or just adding both aliases
  #
  # Encapsulates the common pattern of:
  #
  #   alias_method :foo_without_feature, :foo
  #   alias_method :foo, :foo_with_feature
  #
  # With this, you simply do:
  #
  #   alias_method_chain :foo, :feature
  #
  # And both aliases are set up for you.
  #
  # Query and bang methods (foo?, foo!) keep the same punctuation:
  #
  #   alias_method_chain :foo?, :feature
  #
  # is equivalent to
  #
  #   alias_method :foo_without_feature?, :foo?
  #   alias_method :foo?, :foo_with_feature?
  #
  # so you can safely chain foo, foo?, foo! and/or foo= with the same feature.
  def alias_method_chain(target, feature)
    # Strip out punctuation on predicates, bang or writer methods since
    # e.g. target?_without_feature is not a valid method name.
    aliased_target, punctuation = target.to_s.sub(/([?!=])$/, ''), $1
    yield(aliased_target, punctuation) if block_given?

    with_method = "#{aliased_target}_with_#{feature}#{punctuation}"
    without_method = "#{aliased_target}_without_#{feature}#{punctuation}"

    alias_method without_method, target
    alias_method target, with_method

    case
    when public_method_defined?(without_method)
      public target
    when protected_method_defined?(without_method)
      protected target
    when private_method_defined?(without_method)
      private target
    end
  end
end
