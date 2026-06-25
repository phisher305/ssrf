 This bug happens because the SMS gateway test feature lets a user provide any gateway_url, then the backend connects
  to that URL before checking whether the user is allowed to test that SMS configuration.

  Because of that order-of-operations flaw, an attacker can make the server send requests to internal systems that are
  not exposed to the internet. In this lab, the vulnerable backend reaches an internal flag service and leaks the
  response. The error message also exposes the generated OTP inside the failed outbound request URL.

  #silyBugBounty
