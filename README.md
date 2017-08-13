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
## example
```ruby
jwt = JWT.new
puts jwt.encode
```

## License
under the LGPL 3.0 License:
- see LICENSE file
