MRuby::Gem::Specification.new('mruby-libjwt') do |spec|
  spec.license = 'LGPL'
  spec.authors = 'HAMANO Tsukasa'
  spec.linker.libraries << 'jwt'
end
