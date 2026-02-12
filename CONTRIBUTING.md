# Contributing to WS-Strike

Thank you for considering contributing to WS-Strike! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

1. **Description** - A clear description of the bug
2. **Steps to Reproduce** - Detailed steps to reproduce the issue
3. **Expected Behavior** - What you expected to happen
4. **Actual Behavior** - What actually happened
5. **Environment** - Burp Suite version, Java version, OS

### Suggesting Features

Feature requests are welcome! Please create an issue with:

1. **Description** - Clear description of the feature
2. **Use Case** - Why this feature would be useful
3. **Proposed Solution** - If you have ideas on implementation

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test your changes** with Burp Suite
5. **Commit with a descriptive message**
   ```bash
   git commit -m "Add feature: description"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**

## Code Guidelines

### Java Style

- Use 4 spaces for indentation
- Follow standard Java naming conventions
- Keep methods focused and concise
- Add comments for complex logic
- Handle exceptions appropriately

### UI Guidelines

- Maintain consistent look with existing panels
- Use monospace fonts for code/data display
- Provide user feedback for long operations
- Include tooltips for non-obvious functionality

### Security Considerations

Since this is a security tool:

- **Input Validation** - Validate and sanitize all user inputs
- **No Hardcoded Secrets** - Never commit credentials or tokens
- **Safe Regex** - Avoid patterns vulnerable to ReDoS
- **Thread Safety** - Use proper synchronization for shared state

## Testing

Before submitting:

1. Build the JAR successfully
2. Load in Burp Suite (both Pro and Community if possible)
3. Test with various WebSocket protocols
4. Verify no regressions in existing functionality

## Project Structure

```
ws-strike/
├── src/main/java/wsstrike/
│   ├── WSStrikeExtension.java   # Entry point
│   ├── WSStrikePanel.java       # UI panels
│   ├── WSConnection.java        # WebSocket client
│   ├── ProtocolCodec.java       # Protocol handling
│   ├── FrameEntry.java          # Data model
│   └── Payloads.java            # Payload lists
└── assets/                       # Screenshots
```

## Areas for Contribution

- Additional protocol support (Phoenix, Pusher, etc.)
- Binary frame handling (Protobuf, MessagePack)
- Response pattern matching in Fuzzer
- Improved UI/UX
- Documentation and examples
- Bug fixes

## Questions?

Feel free to open an issue for any questions about contributing.

Thank you for helping improve WS-Strike!
