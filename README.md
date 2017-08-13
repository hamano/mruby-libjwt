# mruby-libjwt   [![Build Status](https://travis-ci.org/hamano/mruby-libjwt.svg?branch=master)](https://travis-ci.org/hamano/mruby-libjwt)
JWT class
## install by mrbgems
- add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :github => 'hamano/mruby-libjwt'
end
```
## encode example
```ruby
> jwt = JWT.new
 => #<JWT:0x5564b7bcf000>
> jwt.add_grants('{"sub":"1234567890","name": "John Doe","admin": true}')
 => #<JWT:0x5564b7bcf000>
> jwt.set_alg(JWT::ALG_HS256, "secret")
 => #<JWT:0x5564b7bcf000>
> jwt.encode
 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.a2ce1BjLKoQZ2sWjrieL7mb-eHsOne0sA1vUcW88Tns"
```

## License
under the LGPL 3.0 License:
- see LICENSE file
