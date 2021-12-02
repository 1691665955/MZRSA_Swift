Pod::Spec.new do |spec|
  spec.name         = "MZRSA_Swift"
  spec.version      = "0.0.1"
  spec.summary      = "MZRSA_Swift是一个轻量级框架，框架功能包含RSA加密/解密Data、RSA加密/解密String，支持字符串密钥和文件密钥"
  spec.homepage     = "https://github.com/1691665955/MZRSA_Swift"
  spec.authors         = { 'MZ' => '1691665955@qq.com' }
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.source = { :git => "https://github.com/1691665955/MZExtension.git", :tag => spec.version}
  spec.platform     = :ios, "8.0"
  spec.swift_version = '4.2'
  spec.source_files  = "MZRSA.swift"
end
