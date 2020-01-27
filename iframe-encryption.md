# Passing data securely via iFrame

A Quikly campaign can be configured to be accessible only if a verified user token or identifier is present in the URL.

This token can be used to bypass normal user login in a campaign to provide a more seamless experience.

## Signed Parameters
The samples below do not encrypt the data; they only provide a signature to ensure that the data is not tampered with in transit.

### Ruby

```erb
<%
require 'openssl'
data = "user-id-here"
hmac = OpenSSL::HMAC.hexdigest('sha1', "shared secret here", data)
@signed_user_id = "#{data}--#{hmac}
%>

<iframe src="https://www.quikly.com/q/[campaign-id]?uid=<%= @signed_user_id %>" />

```

### PHP
```php
<?php
$data = "user-id-here";
$hmac = hash_hmac('sha1', $data, "shared secret here");
$signed_user_id = "{$data}--{$hmac}";
?>

<iframe src="https://www.quikly.com/q/[campaign-id]?uid=<?php echo $signed_user_id ?>" />
```

## Encrypted Parameters
These samples encrypt the data using a shared secret and a random salt.

### Ruby on Rails

#### Encryption
```erb
<%
data = "user-id-here"
shared_secret = "shared secret here"
length = ActiveSupport::MessageEncryptor.key_len
salt = SecureRandom.hex length
key = ActiveSupport::KeyGenerator.new(shared_secret).generate_key salt, length
message_encryptor = ActiveSupport::MessageEncryptor.new key
encrypted_data = message_encryptor.encrypt_and_sign data
@encrypted_parameter = "#{salt}$$#{encrypted_data}"
%>

<iframe src="https://www.quikly.com/q/[campaign-id]?p=<%= @encrypted_parameter %>" />

```

#### Decryption
```ruby
shared_secret = "shared secret here"
length = ActiveSupport::MessageEncryptor.key_len
salt, encrypted_data = @encrypted_parameter.split("$$")
key = ActiveSupport::KeyGenerator.new(shared_secret).generate_key salt, length
message_encryptor = ActiveSupport::MessageEncryptor.new key
decrypted_data = message_encryptor.decrypt_and_verify(encrypted_data)
```

### OpenSSL AES-256-CBC between PHP and Ruby

#### PHP
```php
<?php
const PASSWORD = '32-character-shared-secret-here-';
const CIPHER_METHOD = 'AES-256-CBC';

function encrypt($str) {
    $iv_length = openssl_cipher_iv_length(CIPHER_METHOD);
    $iv = random_bytes($iv_length);
    $val = openssl_encrypt($str, CIPHER_METHOD, PASSWORD, OPENSSL_RAW_DATA, $iv);
    $data = base64_encode($iv . ":" . $val);
    return strtr($data, '+/', '-_');
}

function decrypt($str) {
    $val = strtr($str, '-_', '+/');
    $val = base64_decode($val);
    $parts = explode(':', $val);
    $iv = $parts[0];
    $data = $parts[1];
    return openssl_decrypt($data, CIPHER_METHOD, PASSWORD, OPENSSL_RAW_DATA, $iv);
}

$plain_data = "super secret string";
$encrypted = encrypt($plain_data);
// $decrypted = decrypt($encrypted);
?>
<iframe src="https://www.quikly.com/q/[campaign-id]?p=<?php echo $encrypted ?>" />
```

#### Ruby

```erb
<%
require 'openssl'
require 'base64'

PASSWORD = '32-character-shared-secret-here-'
CIPHER_METHOD = 'AES-256-CBC'

def encrypt(str)
  cipher = OpenSSL::Cipher.new(CIPHER_METHOD)
  cipher.encrypt
  iv = cipher.random_iv
  cipher.key = PASSWORD
  data = cipher.update(str) + cipher.final
  #return "#{iv}:#{data}"
  Base64.urlsafe_encode64("#{iv}:#{data}")
end

def decrypt(str)
  iv, data = Base64.urlsafe_decode64(str).split(":")
  cipher = OpenSSL::Cipher.new(CIPHER_METHOD)
  cipher.decrypt
  cipher.key = PASSWORD
  cipher.iv = iv
  cipher.update(data) + cipher.final
end

plain_data = "super secret string";
@encrypted = encrypt(plain_data)
# decrypted = decrypt(encrypted)
%>

<iframe src="https://www.quikly.com/q/[campaign-id]?p=<%= @encrypted %>" />
```
