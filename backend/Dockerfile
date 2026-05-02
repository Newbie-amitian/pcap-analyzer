FROM node:20-slim

# Install TShark (Wireshark CLI) - FIXED syntax
RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first (for caching)
COPY package*.json ./

# Install dependencies (use --production for smaller image)
RUN npm install --production

# Copy the rest of the files
COPY . .

# Create directories for PCAP files
RUN mkdir -p tmp_pcaps tmp_exports

# Expose port (Render sets PORT env var automatically)
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:4000/pcap/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))" || exit 1

# Start the server
CMD ["node", "index.js"]
