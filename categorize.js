/* categorize.js — auto-categorization heuristic for self-hosted services.
 *
 * Loaded as a classic <script src="categorize.js"> — exposes two globals on window:
 *   window.KEYWORD_RULES    — edit this map to add/override categories
 *   window.autoCategorize   — function(name, url, desc) -> { category, matched }
 *
 * RULE FORMAT
 *  Each category maps to a list of substrings (lowercase) tested against the
 *  service's name + description + URL host + URL path. First match wins, in
 *  the order categories are declared (see RANK below).
 *
 * EDITING
 *  Add a keyword to an existing category's array, or add a new category:
 *     'Tools': ['filebrowser', 'speedtest',' nikki']
 *  Keep keywords lowercase. Multi-word phrases are fine ('ci server').
 *
 *  The RANK array at the top controls category order during matching —
 *  categories listed earlier win ties when several keywords match.
 */

const KEYWORD_RULES = {
  Monitoring:    ['grafana', 'prometheus', 'kuma', 'uptime', 'alertmanager', 'loki', 'zabbix', 'pyroscope', 'sabnzbd-logs', 'kibana', 'observium', 'munin', 'sensu', 'netdata', 'glances', 'wakatime'],
  Security:      ['vault', 'warden', 'bitwarden', 'authelia', 'authentik', 'keycloak', 'vaultwarden', 'tor-proxy', 'onion routing', 'onion relay', 'torservice', 'clamav', 'fail2ban', 'wazuh', 'crowdsec', 'unifi-protect'],
  Network:       ['pi-hole', 'pihole', 'adguard', 'wireguard', 'openvpn', 'tailscale', 'wg-easy', 'unbound', 'dnsmasq', 'traefik', 'nginx-proxy-manager', 'npmplus', 'cloudflare-tunnel', 'blocky', 'zerotier', 'caddy', 'nginx', 'haproxy'],
  Media:         ['jellyfin', 'plex', 'emby', 'navidrome', 'audiobookshelf', 'komga', 'kavita', 'komf', 'sonarr', 'radarr', 'lidarr', 'lidarrhy', 'prowlarr', 'readarr', 'tautulli', 'overseerr', 'ombi', 'bazarr', 'whisperasr', 'focalpoint', 'audiobook', 'immich', 'photo pris', 'photoprism', 'lychee', 'piwigo', 'tubearchivist', 'jellyseerr'],
  Productivity:  ['nextcloud', 'owncloud', 'joplin', 'paperless', 'outline', 'wikijs', 'wiki', 'bookstack', 'etherpad', 'codimd', 'hedgedoc', 'trilium', 'notes', 'docmost', 'draw.io', 'excalidraw', 'flatnotes', 'memos'],
  Files:         ['filebrowser', 'duplicati', 'restic-rest-server', 'borg', 'filerun', 'nextcloud-files', 'seafile', 'rutorrent', 'transmission', 'qbittorrent', 'deluge', 'sabnzbd', 'nzbget', 'syncthing', 'minio', 'garage', 'rclone-webui', 'sftpgo', 'filezilla'],
  Dev:           ['gitea', 'gitea-actions', 'forgeo', 'gitlab', 'forgejo', 'gitea', 'git', 'woodpecker', 'drone', 'jenkins', 'teampass', 'hubgit', 'code', 'coder', 'code-server', 'terminal', 'theia', 'kasm', 'docker', 'portainer', 'dockge', 'komodo', 'dokploy', 'kubernetes', 'k9s', 'mkdocs-dev', 'ruffasr', 'cinny-dev', 'coolify', 'uptime-kuma', 'n8n'],
  Communication: ['matrix', 'element', 'synapse', 'conduit', 'dendrite', 'mastodon', 'pleroma', 'akkoma', 'misskey', 'firefish', 'xmpp', 'prosody', 'ejabberd', 'rocketchat', 'mattermost', 'zulip', 'cinny', 'ntfy', 'ntfy-sh', 'gotify', 'vaultwarden-notify', 'simplelogin'],
  Home:          ['homeassistant', 'home-assistant', 'home assistant', 'home automation', 'home automation', 'hass', 'mosquitto', 'mqtt', 'zigbee2mqtt', 'zwave', 'frigate', 'esphome', 'pi-kiosk', 'scrypted', 'domoticz', 'openhab', 'node-red', 'govee'],
  Finance:       ['firefly', 'fireflyiii', 'maybe', 'actual', 'budget', 'wallet', 'invoice', 'expense', 'ledger'],
  AI:            ['semantickernel', 'open-webui', 'open webui', 'webui', 'ollama', 'litellm', 'llamacpp', 'stable-diffusion', 'comfyui', 'automatic1111', 'text-generation-webui', 'openai', 'librechat', 'chatgpt', 'flowise', 'langflow', 'lavague', 'lobe-chat', 'searxng-llm'],
  Search:        ['searxng', 'searx', 'whoogle', 'swhoosearch', 'mwmbl', 'librey', 'yacy', 'sphinx'],
  Database:      ['adminer', 'pgadmin', 'redisinsight', 'mongo-express', 'metabase', 'superset', 'beekeeper', 'dbeaver', 'influxdb-admin', 'mongo', 'redis', 'postgre', 'mysql', 'cockroach'],
  Gaming:        ['steam', 'epic', 'minecraft', 'mc-router', 'palworld', 'gamevault', 'romm', 'retroarch', 'lutris', 'playnite', 'gaming'],
  Books:         ['calibre', 'calibre-web', 'librarian', 'audiobookshelf-books', 'booksonic', 'readarr-books', 'lazy librarian'],
  Money:         ['actual-budget', 'firefly-iii', 'ghostfolio', 'kresus', 'hledger', 'beanconqueror', 'fava'],
  Travel:        ['immich-travel', 'traccar', 'owntracks', 'traefik-travel'],
  Health:        ['tandoor', 'mealie', 'grocy', 'home-assistant-health', 'open-health', 'sleep', 'fitness'],
};

// Order categories are matched. More specific first so e.g. "Firefly III" hits
// Finance (fuzzy) before Productivity (catch-all "budget"). Reorder to taste.
const RANK = [
  'Security', 'Network', 'Monitoring', 'Database', 'AI',
  'Communication', 'Media', 'Files', 'Productivity', 'Dev',
  'Search', 'Home', 'Finance', 'Gaming', 'Books', 'Money', 'Travel', 'Health',
];

function autoCategorize(name, url, desc) {
  const haystack = [name || '', desc || '', hostOf(url), pathOf(url)]
    .join(' ').toLowerCase();

  for (const cat of RANK) {
    const kws = KEYWORD_RULES[cat] || [];
    for (const kw of kws) {
      const k = String(kw).toLowerCase().trim();
      if (!k) continue;
      if (haystack.includes(k)) {
        return { category: cat, matched: k };
      }
    }
  }
  return { category: 'Other', matched: null };
}

function hostOf(url) {
  if (!url) return '';
  try { return new URL(url.startsWith('http') ? url : 'https://' + url).host; } catch { return url; }
}
function pathOf(url) {
  if (!url) return '';
  try { return new URL(url.startsWith('http') ? url : 'https://' + url).pathname; } catch { return ''; }
}

if (typeof window !== 'undefined') {
  window.KEYWORD_RULES = KEYWORD_RULES;
  window.autoCategorize = autoCategorize;
  window.RANK = RANK;
}