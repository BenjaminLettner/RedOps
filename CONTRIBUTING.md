# Contributing to RedOps

Thank you for your interest in contributing to RedOps! This document provides guidelines and information for contributors.

## 🤝 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors
- Remember that this tool is for authorized security testing only

## 🚀 Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- Git
- A code editor (Visual Studio, VS Code, JetBrains Rider, etc.)

### Setting Up Development Environment

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/RedOps.git
   cd RedOps
   ```

2. **Create a development branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Build and test**
   ```bash
   cd RedOps
   dotnet build
   dotnet run
   ```

## 📋 How to Contribute

### Reporting Bugs

Before creating bug reports, please check the [issue tracker](https://github.com/benjaminlettner/RedOps/issues) to avoid duplicates.

**Bug Report Template:**
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. See error

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
- OS: [e.g. Windows 11, Ubuntu 22.04]
- .NET Version: [e.g. 8.0.1]
- RedOps Version: [e.g. 1.0.0]
```

### Suggesting Features

Feature requests are welcome! Please provide:

- **Clear description** of the feature
- **Use case** - why is this feature needed?
- **Proposed implementation** (if you have ideas)
- **Cyber kill chain phase** it belongs to

### Pull Requests

1. **Follow the roadmap** - Check [ROADMAP.md](ROADMAP.md) for planned features
2. **Create focused PRs** - One feature per pull request
3. **Write tests** - Include unit tests for new functionality
4. **Update documentation** - Update README.md and code comments
5. **Follow coding standards** - See style guide below

## 🎯 Development Areas

### High Priority
- **Phase 1.2**: Web Application Reconnaissance
- **Phase 1.3**: OSINT & Information Gathering
- **Plugin Development**: New reconnaissance modules
- **Performance Optimization**: Scanning speed improvements
- **Cross-platform Testing**: Linux/macOS compatibility

### Medium Priority
- **UI Enhancements**: Better visualization and reporting
- **Configuration Management**: Advanced settings
- **Error Handling**: Improved resilience
- **Documentation**: More examples and tutorials

### Plugin Development

RedOps uses a plugin architecture. Here's how to create a new plugin:

```csharp
using RedOps.Core.Plugins;
using System.Threading.Tasks;

namespace RedOps.Plugins.MyPlugin
{
    public class MyReconPlugin : IPlugin
    {
        public string Name => "My Reconnaissance Tool";
        public string Description => "Description of what this plugin does";
        public PluginCategory Category => PluginCategory.Reconnaissance;

        public async Task ExecuteAsync(PluginContext context)
        {
            context.Logger.Information("Starting my reconnaissance tool...");
            
            // Your plugin logic here
            await DoReconnaissanceWork();
            
            context.Logger.Information("Reconnaissance completed successfully");
        }

        private async Task DoReconnaissanceWork()
        {
            // Implementation details
        }
    }
}
```

## 📝 Coding Standards

### C# Style Guidelines

- **Naming Conventions**:
  - Classes: `PascalCase`
  - Methods: `PascalCase`
  - Variables: `camelCase`
  - Constants: `UPPER_CASE`
  - Private fields: `_camelCase`

- **Code Organization**:
  - One class per file
  - Logical grouping of methods
  - Clear separation of concerns

- **Documentation**:
  ```csharp
  /// <summary>
  /// Performs network discovery on the specified IP range
  /// </summary>
  /// <param name="ipRange">IP range in CIDR notation (e.g., 192.168.1.0/24)</param>
  /// <returns>List of discovered hosts</returns>
  public async Task<List<NetworkHost>> DiscoverHostsAsync(string ipRange)
  {
      // Implementation
  }
  ```

### Error Handling

- Use structured logging with Serilog
- Provide meaningful error messages
- Handle network timeouts gracefully
- Validate user input

```csharp
try
{
    var result = await ScanPortAsync(target, port);
    Logger.Information("Port scan completed for {Target}:{Port}", target, port);
    return result;
}
catch (SocketException ex)
{
    Logger.Warning("Network error scanning {Target}:{Port}: {Error}", target, port, ex.Message);
    return null;
}
catch (Exception ex)
{
    Logger.Error(ex, "Unexpected error during port scan of {Target}:{Port}", target, port);
    throw;
}
```

### Testing

- Write unit tests for new functionality
- Use descriptive test names
- Test both success and failure scenarios
- Mock external dependencies

```csharp
[Test]
public async Task ScanPortAsync_ValidTarget_ReturnsOpenPortInfo()
{
    // Arrange
    var scanner = new PortScanner();
    var target = "127.0.0.1";
    var port = 80;

    // Act
    var result = await scanner.ScanPortAsync(target, port);

    // Assert
    Assert.IsNotNull(result);
    Assert.AreEqual(port, result.Port);
}
```

## 🔄 Development Workflow

### Branch Naming
- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring

### Commit Messages
Follow conventional commit format:
```
type(scope): description

feat(network): add subnet scanning capability
fix(ui): resolve menu navigation issue
docs(readme): update installation instructions
```

### Pull Request Process

1. **Update your branch**
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run tests**
   ```bash
   dotnet test
   dotnet build
   ```

3. **Create pull request**
   - Use descriptive title
   - Reference related issues
   - Include testing instructions
   - Add screenshots if UI changes

### Review Process

All PRs require:
- ✅ Code review from maintainer
- ✅ All tests passing
- ✅ Documentation updated
- ✅ No merge conflicts

## 🛡️ Security Considerations

### Responsible Development
- **No real exploits** in main codebase
- **Input validation** for all user inputs
- **Rate limiting** for network operations
- **Clear warnings** for potentially dangerous operations

### Testing Guidelines
- Test only on systems you own
- Use isolated test environments
- Document any network requirements
- Include safety checks in code

## 📚 Resources

- [.NET Documentation](https://docs.microsoft.com/en-us/dotnet/)
- [Spectre.Console Documentation](https://spectreconsole.net/)
- [Serilog Documentation](https://serilog.net/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 🎉 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for helping make RedOps better! 🚀
