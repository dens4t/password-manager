# SecurePass

A secure password manager built with Go and Gin framework.

## Overview

SecurePass is a modern password management solution that provides secure storage and management of your credentials with a clean web interface.

## Features

- 🔐 Secure password storage with encryption
- 🌐 Web-based interface with modern design
- 📱 Responsive design for mobile and desktop
- 🔄 Real-time synchronization
- 🔒 End-to-end encryption
- 📊 Password strength analysis
- 🎯 Easy password generation
- 🔗 Secure sharing capabilities

## Tech Stack

- **Backend**: Go 1.25+, Gin framework
- **Database**: SQLite with SQLite3 driver
- **Frontend**: HTML/CSS/JavaScript (from frontend directory)
- **Templates**: Go HTML templates
- **Authentication**: Session-based with secure cookies
- **Deployment**: Cloudflare Tunnel ready

## Project Structure

```
securepass/
├── main.go              # Main application entry point
├── go.mod               # Go module dependencies
├── go.sum               # Dependency checksums
├── .gitignore           # Git ignore rules
├── cloudflared.yml      # Cloudflare Tunnel configuration
├── securepass           # Compiled binary
├── securepass.db        # SQLite database file
├── frontend/            # Frontend assets
├── templates/           # HTML templates
├── server.log           # Server logs
└── tunnel.log           # Tunnel logs
```

## Prerequisites

- Go 1.25 or later
- Git
- SQLite3 (optional, included with Go driver)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/securepass.git
   cd securepass
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Build the application**
   ```bash
   go build -o securepass
   ```

4. **Run the application**
   ```bash
   ./securepass
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:8080`

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```
PORT=8080
DB_PATH=securepass.db
SESSION_SECRET=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here
```

### Cloudflare Tunnel
To expose your application via Cloudflare Tunnel:

1. Install Cloudflare Tunnel:
   ```bash
   # Download and install cloudflared
   ```

2. Configure tunnel:
   ```bash
   ./securepass --tunnel
   ```

3. Or use the YAML configuration in `cloudflared.yml`

## Development

### Running in Development Mode
```bash
go run main.go
```

### Building for Production
```bash
go build -ldflags="-s -w" -o securepass
```

### Running Tests
```bash
go test ./...
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate user |
| GET | `/dashboard` | User dashboard |
| GET | `/passwords` | List all passwords |
| POST | `/passwords` | Create new password |
| GET | `/passwords/{id}` | Get password by ID |
| PUT | `/passwords/{id}` | Update password |
| DELETE | `/passwords/{id}` | Delete password |
| GET | `/generate` | Generate secure password |

## Security Features

- AES-256 encryption for stored passwords
- Secure session management
- Password strength validation
- Brute-force protection
- XSS and CSRF protection
- Secure headers (HSTS, CSP)
- Input validation and sanitization

## Deployment

### Docker Deployment
```bash
docker build -t securepass .
docker run -p 8080:8080 securepass
```

### Systemd Service
```bash
sudo cp securepass.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable securepass
sudo systemctl start securepass
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please:
1. Check the documentation
2. Open an issue on GitHub
3. Contact the maintainers

## Roadmap

- [ ] Mobile app (iOS/Android)
- [ ] Browser extensions
- [ ] Two-factor authentication
- [ ] Password health reports
- [ ] Emergency access
- [ ] Password breach monitoring
- [ ] Family sharing

## Acknowledgments

- [Gin Web Framework](https://gin-gonic.com/)
- [SQLite](https://www.sqlite.org/)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
- All contributors and supporters