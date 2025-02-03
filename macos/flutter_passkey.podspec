Pod::Spec.new do |s|
    s.name             = 'flutter_passkey'
    s.version          = '1.0.5'
    s.summary          = 'A Flutter plugin for using Passkey easily.'
    s.description      = <<-DESC
  Flutter plugin for using Passkey easily.
                         DESC
    s.homepage         = 'https://github.com/AuthenTrend/flutter_passkey'
    s.license          = { :file => '../LICENSE' }
    s.author           = { 'AuthenTrend Technology Inc.' => 'joshua.lin@authentrend.com' }
    s.source           = { :path => '.' }
    s.platform         = :osx, '10.11'
    s.source_files     = 'Classes/**/*'
    s.dependency 'Flutter'
    s.swift_version    = '5.5'
  end
  