# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ffi-pkcs11/version'

Gem::Specification.new do |spec|
  spec.name          = "ffi-pkcs11"
  spec.version       = Pkcs11::VERSION
  spec.authors       = ["Vincent Touchard"]
  spec.email         = ["touchardv@gmail.com"]

  spec.summary       = %q{Minimalistic Ruby FFI bindings for using a "Cryptoki" (PKCS11) library.}
  spec.homepage      = "https://github.com/touchardv/ffi-pkcs11"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "ffi", "~> 1.9"
  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "pry-byebug"
  spec.add_development_dependency "rake", ">= 12.3.3"
  spec.add_development_dependency "rspec", "~> 3.0"
end
