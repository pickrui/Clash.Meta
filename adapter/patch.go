package adapter

// UrlTestCheck reports a finished probe. alive is false when the request
// failed or did not satisfy the expected status, so a positive delay alone
// never means the proxy is usable for that URL.
type UrlTestCheck func(url string, name string, delay uint16, alive bool)

var UrlTestHook UrlTestCheck
