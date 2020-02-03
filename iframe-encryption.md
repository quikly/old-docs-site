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
    $data = openssl_encrypt($str, CIPHER_METHOD, PASSWORD, OPENSSL_RAW_DATA, $iv);
    return bin2hex($iv).":".bin2hex($data);
}

function decrypt($str) {
    $parts = explode(':', $str);
    $iv = hex2bin($parts[0]);
    $data = hex2bin($parts[1]);
    return openssl_decrypt($data, CIPHER_METHOD, PASSWORD, OPENSSL_RAW_DATA, $iv);
}

$values = [
  'email' => 'email@example.com',
  'pid' => '+ < > # % { } | \ ^ ~ [ ] `'
];

$plain_data = http_build_query($values);

// multiple values can be encrypted in the same string:
$encrypted = encrypt($plain_data);
$decrypted = decrypt($encrypted);

parse_str($decrypted, $output);
echo "Encrypted: $encrypted";
echo "\nDecrypted: ";
var_dump($output)
?>
```

#### Ruby

```ruby
require 'openssl'
require 'base64'

PASSWORD = '32-character-shared-secret-here-'
CIPHER_METHOD = 'AES-256-CBC'

# for generating
def encrypt(str)
  cipher = OpenSSL::Cipher.new(CIPHER_METHOD)
  cipher.encrypt
  iv = cipher.random_iv
  cipher.key = PASSWORD
  data = cipher.update(str) + cipher.final
  "#{bin_to_hex(iv)}:#{bin_to_hex(data)}"
end

def decrypt(str)
  iv, data = str.split(":").map { |v| hex_to_bin(v) }
  cipher = OpenSSL::Cipher.new(CIPHER_METHOD)
  cipher.decrypt
  cipher.key = PASSWORD
  cipher.iv = iv
  cipher.update(data) + cipher.final
end

def bin_to_hex(s)
  s.unpack('H*').first
end

def hex_to_bin(s)
  [s].pack('H*')
end

values = {
  email: 'email@example.com',
  pid: '+ < > # % { } | \ ^ ~ [ ] `'
}

plain_data = URI.encode_www_form(values)

@encrypted = encrypt(plain_data)
@decrypted = decrypt(@encrypted)
puts "Encrypted: #{@encrypted}\nDecrypted: #{URI.decode_www_form(@decrypted)}\n\n"
```
