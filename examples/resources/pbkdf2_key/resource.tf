resource "random_password" "example" {}

resource "pbkdf2_key" "example" {
  password = random_password.example.result
  # Output for https://github.com/appkins/pbkdf-subtle
  format = "{{ printf \"%s:%s\" (b64enc .Salt) (b64enc .Key) }}"
}
