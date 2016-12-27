# Python module for HMAC Authentication with Kong
This is a python module for generating HTTP request headers for HMAC authentication with [Kong](https://getkong.org/).
More specifically, Kong's [HMAC Authentication Plugin](https://getkong.org/plugins/hmac-authentication/).

This module was written for load testing with [Locust](http://locust.io/) and used in conjuction with [Locust Docker](https://github.com/peter-evans/locust-docker).

## Usage

GET request:
```python
from kong_hmac import generate_request_headers
import requests

key_id = 'my-key-id'
secret = 'my-secret'
url = 'https://example.com/api/resource'
get_request_headers = generate_request_headers(key_id, secret, url)
r = requests.get(url, headers=get_request_headers)
print 'Response code: %d\n' % r.status_code
print r.text
```  
POST request:
```python
from kong_hmac import generate_request_headers
import request

key_id = 'my-key-id'
secret = 'my-secret'
url = 'https://example.com/api/resource'
content_type = 'application/json'
payload = open('payload.json', 'r').read()
post_request_headers = generate_request_headers(key_id, secret, url, payload, content_type)
r = requests.post(url, headers=post_request_headers, data=payload)
print 'Response code: %d\n' % r.status_code
print r.text
```
payload.json:
```json
{
	"key1": "value1",
	"key2": "value2"
}
```

## Reference

[HTTP Signatures Specification](https://tools.ietf.org/html/draft-cavage-http-signatures-00)

## License

MIT License - see the [LICENSE](LICENSE) file for details