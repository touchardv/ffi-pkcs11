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

### Low-level API

In order to use a PKCS11 function, one should prefix the function with the `Pkcs11` module name e.g.

	result = Pkcs11.C_Initialize(nil)
	if result == Pkcs11::CKR_OK
	[...]
	

### High-level API

Coming soon (TM).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/rspec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

The tests are using a software-only PKCS11 implementation [SoftHSM](https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2).

It is initialized using the following command:
`softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 1234`

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/touchardv/ffi-pkcs11.

