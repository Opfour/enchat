#!/bin/bash
set -e

# 🚀 NTFY SERVER SETUP FOR ENCHAT
# Complete self-hosted ntfy deployment script

echo "🔐 NTFY SERVER SETUP FOR ENCHAT"
echo "================================"
echo

# Color functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "Don't run this script as root. Run as normal user with sudo privileges."
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages
install_packages() {
    if command_exists apt; then
        sudo apt update
        sudo apt install -y "$@"
    elif command_exists yum; then
        sudo yum install -y "$@"
    elif command_exists dnf; then
        sudo dnf install -y "$@"
    else
        error "No supported package manager found"
        exit 1
    fi
}

# Get user input
echo "📋 Configuration Setup"
echo "---------------------"

read -p "🌐 Server domain/IP (e.g., ntfy.yourdomain.com): " DOMAIN
read -p "🔌 Port (default 80 for HTTP, 443 for HTTPS): " PORT
read -p "🔒 Enable HTTPS with Let's Encrypt? [y/N]: " ENABLE_SSL
read -p "📧 Email for Let's Encrypt (if HTTPS enabled): " EMAIL
read -p "🐳 Use Docker installation? [Y/n]: " USE_DOCKER

# Set defaults
PORT=${PORT:-80}
USE_DOCKER=${USE_DOCKER:-Y}
ENABLE_SSL=${ENABLE_SSL:-N}

# Set URL scheme
if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
    URL_SCHEME="https"
else
    URL_SCHEME="http"
fi

# Validate domain
if [[ -z "$DOMAIN" ]]; then
    error "Domain is required"
    exit 1
fi

# Create ntfy user and directories
info "Creating ntfy user and directories..."
sudo useradd -r -s /bin/false ntfy 2>/dev/null || true
sudo mkdir -p /etc/ntfy
sudo mkdir -p /var/lib/ntfy
sudo mkdir -p /var/log/ntfy
sudo chown ntfy:ntfy /var/lib/ntfy /var/log/ntfy

# Docker Installation
if [[ "$USE_DOCKER" =~ ^[Yy]$ ]]; then
    info "Setting up Docker-based ntfy server..."
    
    # Install Docker if not present
    if ! command_exists docker; then
        info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        rm get-docker.sh
    fi

    # Install Docker Compose if not present
    if ! command_exists docker-compose; then
        info "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    fi

    # Create ntfy config
    info "Creating ntfy configuration..."
    sudo tee /etc/ntfy/server.yml > /dev/null <<EOF
# ntfy server configuration for Enchat
base-url: "${URL_SCHEME}://$DOMAIN"
listen-http: ":80"
cache-file: "/var/lib/ntfy/cache.db"
attachment-cache-dir: "/var/lib/ntfy/attachments"
auth-file: "/var/lib/ntfy/auth.db"
auth-default-access: "read-write"

# Rate limiting (generous for chat usage)
visitor-request-limit-burst: 200
visitor-request-limit-replenish: "10s"
visitor-message-daily-limit: 5000

# Logging
log-level: info
log-file: "/var/log/ntfy/ntfy.log"

# CORS for web access
EOF

    # Create Docker Compose file
    info "Creating Docker Compose configuration..."
    mkdir -p ~/ntfy-server
    
    if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
        # HTTPS setup with Nginx proxy and Let's Encrypt
        tee ~/ntfy-server/docker-compose.yml > /dev/null <<EOF
version: '3.8'

services:
  ntfy:
    image: binwiederhier/ntfy
    container_name: ntfy
    command:
      - serve
    environment:
      - NTFY_BASE_URL=https://$DOMAIN
      - NTFY_LISTEN_HTTP=:80
    volumes:
      - /var/lib/ntfy:/var/lib/ntfy
      - /etc/ntfy:/etc/ntfy
      - /var/log/ntfy:/var/log/ntfy
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ntfy.rule=Host(\`$DOMAIN\`)"
      - "traefik.http.routers.ntfy.entrypoints=websecure"
      - "traefik.http.routers.ntfy.tls.certresolver=letsencrypt"

  traefik:
    image: traefik:v2.9
    container_name: traefik
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=$EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt
    restart: unless-stopped
EOF
        
        # Create letsencrypt directory
        mkdir -p ~/ntfy-server/letsencrypt
        chmod 600 ~/ntfy-server/letsencrypt
    else
        # HTTP-only setup
        tee ~/ntfy-server/docker-compose.yml > /dev/null <<EOF
version: '3.8'

services:
  ntfy:
    image: binwiederhier/ntfy
    container_name: ntfy
    command:
      - serve
    environment:
      - NTFY_BASE_URL=http://$DOMAIN:$PORT
      - NTFY_LISTEN_HTTP=:80
    volumes:
      - /var/lib/ntfy:/var/lib/ntfy
      - /etc/ntfy:/etc/ntfy
      - /var/log/ntfy:/var/log/ntfy
    ports:
      - "$PORT:80"
    restart: unless-stopped
EOF
    fi

    # Start the services
    info "Starting ntfy server..."
    cd ~/ntfy-server
    sudo docker-compose up -d

else
    # Manual Installation
    info "Setting up manual ntfy installation..."
    
    # Install dependencies
    info "Installing dependencies..."
    install_packages wget curl

    # Download and install ntfy
    info "Downloading ntfy binary..."
    NTFY_VERSION=$(curl -s https://api.github.com/repos/binwiederhier/ntfy/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget "https://github.com/binwiederhier/ntfy/releases/download/$NTFY_VERSION/ntfy_${NTFY_VERSION#v}_linux_amd64.tar.gz"
    tar -xzf "ntfy_${NTFY_VERSION#v}_linux_amd64.tar.gz"
    sudo cp ntfy /usr/local/bin/
    sudo chmod +x /usr/local/bin/ntfy
    rm -f "ntfy_${NTFY_VERSION#v}_linux_amd64.tar.gz" ntfy

    # Create configuration
    info "Creating ntfy configuration..."
    if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
        BASE_URL="${URL_SCHEME}://$DOMAIN"
    else
        BASE_URL="${URL_SCHEME}://$DOMAIN:$PORT"
    fi
    
    sudo tee /etc/ntfy/server.yml > /dev/null <<EOF
# ntfy server configuration for Enchat
base-url: "$BASE_URL"
listen-http: ":$PORT"
cache-file: "/var/lib/ntfy/cache.db"
attachment-cache-dir: "/var/lib/ntfy/attachments"
auth-file: "/var/lib/ntfy/auth.db"
auth-default-access: "read-write"

# Rate limiting (generous for chat usage)
visitor-request-limit-burst: 200
visitor-request-limit-replenish: "10s"
visitor-message-daily-limit: 5000

# Logging
log-level: info
log-file: "/var/log/ntfy/ntfy.log"

# CORS for web access
EOF

    # Create systemd service
    info "Creating systemd service..."
    sudo tee /etc/systemd/system/ntfy.service > /dev/null <<EOF
[Unit]
Description=ntfy server
After=network.target

[Service]
Type=exec
User=ntfy
Group=ntfy
ExecStart=/usr/local/bin/ntfy serve --config /etc/ntfy/server.yml
Restart=on-failure
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    # Set up firewall
    if command_exists ufw; then
        info "Configuring firewall..."
        sudo ufw allow $PORT
        if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
            sudo ufw allow 443
        fi
    fi

    # Start and enable service
    info "Starting ntfy service..."
    sudo systemctl daemon-reload
    sudo systemctl enable ntfy
    sudo systemctl start ntfy
fi

# Setup log rotation
info "Setting up log rotation..."
sudo tee /etc/logrotate.d/ntfy > /dev/null <<EOF
/var/log/ntfy/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 ntfy ntfy
    postrotate
        systemctl reload ntfy 2>/dev/null || true
    endscript
}
EOF

# Wait for service to start
info "Waiting for ntfy to start..."
sleep 5

# Test the installation
info "Testing ntfy installation..."
if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
    NTFY_URL="https://$DOMAIN"
else
    NTFY_URL="http://$DOMAIN:$PORT"
fi

if curl -s "$NTFY_URL/v1/health" >/dev/null; then
    success "ntfy server is running successfully!"
else
    warning "ntfy server may not be responding. Check the logs."
fi

# Create Enchat test script
info "Creating Enchat test script..."
tee ~/test-enchat-ntfy.sh > /dev/null <<EOF
#!/bin/bash
echo "🧪 Testing Enchat with your ntfy server..."
echo "Server: $NTFY_URL"
echo
echo "Run this command to test Enchat with your server:"
echo "enchat --server $NTFY_URL"
echo
echo "Or during setup, enter: $NTFY_URL"
EOF
chmod +x ~/test-enchat-ntfy.sh

# Final instructions
echo
success "🎉 NTFY SERVER SETUP COMPLETE!"
echo "=================================="
echo
info "Server Details:"
echo "  URL: $NTFY_URL"
echo "  Web UI: $NTFY_URL"
echo "  Config: /etc/ntfy/server.yml"
echo "  Logs: /var/log/ntfy/ntfy.log"
echo
info "Enchat Integration:"
echo "  Command: enchat --server $NTFY_URL"
echo "  Or during setup enter: $NTFY_URL"
echo
info "Management Commands:"
if [[ "$USE_DOCKER" =~ ^[Yy]$ ]]; then
    echo "  Status: cd ~/ntfy-server && docker-compose ps"
    echo "  Logs: cd ~/ntfy-server && docker-compose logs -f ntfy"
    echo "  Restart: cd ~/ntfy-server && docker-compose restart"
    echo "  Stop: cd ~/ntfy-server && docker-compose down"
else
    echo "  Status: sudo systemctl status ntfy"
    echo "  Logs: sudo journalctl -u ntfy -f"
    echo "  Restart: sudo systemctl restart ntfy"
    echo "  Stop: sudo systemctl stop ntfy"
fi
echo
info "Test script created: ~/test-enchat-ntfy.sh"
echo
warning "Important Security Notes:"
echo "  - This setup allows anonymous read/write access"
echo "  - For production, consider adding authentication"
echo "  - Monitor your server logs regularly"
echo "  - Keep your server updated"
echo
success "Your self-hosted ntfy server is ready for Enchat! 🚀" 
