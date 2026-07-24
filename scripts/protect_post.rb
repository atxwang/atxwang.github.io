#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "date"
require "io/console"
require "openssl"
require "optparse"
require "yaml"
require "kramdown"
require "kramdown-parser-gfm"

ITERATIONS = 310_000
PROTECTED_EXCERPT = "This article is password protected."
ENCRYPTED_BODY = "<!-- Encrypted article. Run scripts/protect_post.rb --decrypt to restore the Markdown source. -->\n"
PROTECTION_KEYS = %w[protected password_protection].freeze

def parse_post(path)
  source = File.read(path, encoding: "UTF-8")
  match = source.match(/\A---\s*\n(.*?)^---\s*$\n?(.*)\z/m)
  abort "Expected YAML front matter in #{path}" unless match

  metadata = YAML.safe_load(
    match[1],
    permitted_classes: [Date, Time],
    aliases: true
  ) || {}
  [metadata, match[2]]
end

def password_from_environment
  password = ENV["POST_PASSWORD"]
  return password unless password.nil? || password.empty?

  warn "Password: "
  password = $stdin.noecho(&:gets)&.chomp
  warn
  abort "A non-empty password is required." if password.nil? || password.empty?
  password
end

def derive_key(password, salt, iterations)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, 32, "sha256")
end

def encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  iv = OpenSSL::Random.random_bytes(12)
  cipher.key = key
  cipher.iv = iv
  ciphertext = cipher.update(plaintext) + cipher.final + cipher.auth_tag
  [Base64.strict_encode64(iv), Base64.strict_encode64(ciphertext)]
end

def decrypt(ciphertext, iv, key)
  decoded = Base64.strict_decode64(ciphertext)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.decrypt
  cipher.key = key
  cipher.iv = Base64.strict_decode64(iv)
  cipher.auth_tag = decoded[-16, 16]
  (cipher.update(decoded[0...-16]) + cipher.final).force_encoding(Encoding::UTF_8)
end

def write_post(path, metadata, body)
  yaml = YAML.dump(metadata).sub(/\A---\s*\n/, "")
  File.write(path, "---\n#{yaml}---\n#{body}", mode: "w", encoding: "UTF-8")
end

options = { decrypt: false }
OptionParser.new do |parser|
  parser.banner = "Usage: bundle exec ruby scripts/protect_post.rb [--decrypt] POST"
  parser.on("--decrypt", "Restore the encrypted Markdown source for editing") do
    options[:decrypt] = true
  end
end.parse!

path = ARGV.shift
abort "Provide exactly one post path." if path.nil? || !ARGV.empty?
abort "Post not found: #{path}" unless File.file?(path)

metadata, markdown = parse_post(path)
password = password_from_environment

if options[:decrypt]
  protection = metadata["password_protection"]
  abort "#{path} is not password protected." unless metadata["protected"] && protection

  salt = Base64.strict_decode64(protection.fetch("salt"))
  key = derive_key(password, salt, protection.fetch("iterations"))
  restored_markdown = decrypt(
    protection.fetch("source"),
    protection.fetch("source_iv"),
    key
  )
  PROTECTION_KEYS.each { |field| metadata.delete(field) }
  metadata.delete("excerpt") if metadata["excerpt"] == PROTECTED_EXCERPT
  metadata.delete("share-description") if metadata["share-description"] == PROTECTED_EXCERPT
  write_post(path, metadata, restored_markdown)
  puts "Restored the Markdown source in #{path}."
else
  abort "#{path} is already password protected." if metadata["protected"]

  salt = OpenSSL::Random.random_bytes(16)
  key = derive_key(password, salt, ITERATIONS)
  rendered_html = Kramdown::Document.new(markdown, input: "GFM").to_html
  content_iv, encrypted_content = encrypt(rendered_html, key)
  source_iv, encrypted_source = encrypt(markdown, key)

  metadata["protected"] = true
  metadata["excerpt"] = PROTECTED_EXCERPT
  metadata["share-description"] = PROTECTED_EXCERPT
  metadata["password_protection"] = {
    "version" => 1,
    "iterations" => ITERATIONS,
    "salt" => Base64.strict_encode64(salt),
    "iv" => content_iv,
    "content" => encrypted_content,
    "source_iv" => source_iv,
    "source" => encrypted_source
  }
  write_post(path, metadata, ENCRYPTED_BODY)
  puts "Password protected #{path}."
end
