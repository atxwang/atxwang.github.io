theme is beautiful-jekyll by dean attali

## Password-protected articles

This site can publish an article as AES-256-GCM ciphertext and decrypt it locally
in the reader's browser. GitHub Pages serves only the encrypted body; the password
is not stored in the repository or sent to a server.

Protect a post:

```sh
POST_PASSWORD='your password' bundle exec ruby scripts/protect_post.rb _posts/path/to/post.md
```

Restore its Markdown when you need to edit it:

```sh
POST_PASSWORD='your password' bundle exec ruby scripts/protect_post.rb --decrypt _posts/path/to/post.md
```

After editing, protect it again before committing. To test the generated site:

```sh
bundle exec jekyll build --future
POST_PASSWORD='your password' node scripts/test_password_protection.js
```

This is static-site protection, not server-side access control. The encrypted
content can be attacked offline, so use a strong password for genuinely sensitive
material. Old plaintext versions also remain available in public Git history
unless the repository's history is rewritten.
