# FFI::Pkcs11

Minimalistic Ruby FFI bindings for using a "Cryptoki" (PKCS11) library.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ffi-pkcs11'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ffi-pkcs11

## Usage

TODO: Write usage instructions here

## Development

`softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 1234`

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/touchardv/ffi-pkcs11.

