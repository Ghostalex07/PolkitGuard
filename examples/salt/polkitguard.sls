# PolkitGuard Salt State

{% set polkitguard_version = '1.15.0' %}
{% set install_dir = '/usr/local/bin' %}
{% set scan_paths = ['/etc/polkit-1', '/usr/share/polkit-1'] %}
{% set severity = 'high' %}
{% set webhook_url = '' %}

polkitguard_install:
  file.directory:
    - name: {{ install_dir }}
    - makedirs: true
    - mode: 755

  cmd.run:
    - name: curl -L -o {{ install_dir }}/polkitguard https://github.com/Ghostalex07/PolkitGuard/releases/download/v{{ polkitguard_version }}/polkitguard-linux-amd64
    - creates: {{ install_dir }}/polkitguard
    - require:
      - file: polkitguard_install

  file.managed:
    - name: {{ install_dir }}/polkitguard
    - mode: 755

polkitguard_scan_dirs:
  file.directory:
    - name: {{ item }}
    - makedirs: true
    - mode: 755
  {% for path in scan_paths %}
    - {{ path }}
  {% endfor %}

polkitguard_scan:
  cmd.run:
    - name: {{ install_dir }}/polkitguard --path {{ scan_paths|join(',') }} --severity {{ severity }} --format json --output /var/log/polkitguard/scan-{{ salt['cmd.run']('date +\%Y\%m\%d-\%H\%M\%S') }}.json
    - require:
      - cmd: polkitguard_install
    - failhard: True

{% if webhook_url %}
polkitguard_webhook:
  cmd.run:
    - name: curl -s -X POST {{ webhook_url }} -H 'Content-Type: application/json' -d @$(ls -t /var/log/polkitguard/scan-*.json | head -1)
    - onfail:
      - cmd: polkitguard_scan
{% endif %}

polkitguard_cron:
  cron.present:
    - name: {{ install_dir }}/polkitguard --path {{ scan_paths|join(',') }} --severity {{ severity }} --format json --output /var/log/polkitguard/scan-$(date +\%Y\%m\%d-\%H%M%S).json
    - hour: 2
    - minute: 0
    - require:
      - cmd: polkitguard_install

# Polkit rule management
polkit_add_rule:
  file.managed:
    - name: /etc/polkit-1/local.d/{{ salt['cmd.run']('hostname') }}.rules
    - contents: |
        [={{ loop.index }}]
        ResultAny={{ result }}
    - mode: 644