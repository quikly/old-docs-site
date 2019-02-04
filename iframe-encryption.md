# Passing data securely via iFrame

A Quikly campaign can be configured to be accessible only if a verified user token or identifier is present in the URL.

This token can be used to bypass normal user login in a campaign to provide a more seamless experience.

## Code Samples

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
