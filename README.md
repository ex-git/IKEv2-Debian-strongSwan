# IKEv2-Debian-strongSwan


The VPN server setup use Let's Encrypt certificate, so no need to use private certificates.
Authenticate with username and password only.
This script will turn off ipv6 for security concern.
Let's Encrypt certificate will be auto-renew by certbot, so it is a set and forget setup.

For iOS and Mac profile, set encryption algorithm and integrity algorithm as below. 

          <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
          </dict>
