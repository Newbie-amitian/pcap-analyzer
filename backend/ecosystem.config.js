require('dotenv').config({ path: 'D:\\DevSpace\\pcap-analyzer\\backend\\.env' });
module.exports = {
  apps: [
    {
      name: 'pcap-backend',
      script: 'index.js',
      cwd: 'D:\\DevSpace\\pcap-analyzer\\backend',
      watch: true,
      ignore_watch: ['node_modules', 'tmp_pcaps', 'tmp_exports', 'server.log', 'iana_ports_cache.json'],
      autorestart: true,
      exp_backoff_restart_delay: 1000,
      kill_timeout: 3000,
      node_args: '--require dotenv/config',
      env: {
        TSHARK_PATH: 'C:\\Program Files\\Wireshark\\tshark.exe',
        PATH: 'C:\\Program Files\\Wireshark;C:\\Windows\\system32;C:\\Windows;C:\\Program Files\\nodejs'
      }
    }
  ]
};