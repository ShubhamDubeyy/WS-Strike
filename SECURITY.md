# Security Policy

## Responsible Use

WS-Strike is a security testing tool designed for **authorized penetration testing only**.

### Acceptable Use

- Testing applications you own
- Authorized penetration testing engagements
- Security research with proper authorization
- Educational purposes in controlled environments
- Bug bounty programs within scope

### Unacceptable Use

- Testing systems without authorization
- Attacking production systems without permission
- Using for malicious purposes
- Circumventing security controls illegally

## Reporting Security Issues

If you discover a security vulnerability in WS-Strike itself:

1. **Do not** open a public issue
2. Email security concerns to the maintainer
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Features in WS-Strike

The tool includes several security measures:

### Input Sanitization
- CRLF injection prevention in HTTP headers
- URL validation before WebSocket connections
- Input length limits to prevent DoS

### Safe Operations
- ReDoS-resistant regex patterns
- Memory limits on frame history
- Thread-safe concurrent operations

### Design Decisions
- Fuzzer uses standalone connections (not through Burp proxy)
- State chain replay is user-controlled
- No automatic attacks without user action

## Disclaimer

The author is not responsible for misuse of this tool. Users are solely responsible for ensuring they have proper authorization before using WS-Strike against any system.

By using WS-Strike, you agree to use it responsibly and legally.
