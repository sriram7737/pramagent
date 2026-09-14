#!/usr/bin/env sh
set -eu

SOURCE_ROOT=${1:?usage: install-pramagent-hook-boundary.sh SOURCE_ROOT AGENT_GROUP}
AGENT_GROUP=${2:?usage: install-pramagent-hook-boundary.sh SOURCE_ROOT AGENT_GROUP}
INSTALL_ROOT=${PRAMAGENT_HOOK_INSTALL_ROOT:-/opt/pramagent/hook-runtime}
STATE_ROOT=${PRAMAGENT_HOOK_STATE_ROOT:-/var/lib/pramagent}

case "$INSTALL_ROOT" in
    /opt/pramagent/*) ;;
    *) echo "install root must stay below /opt/pramagent" >&2; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "run this installer as root" >&2
    exit 1
fi

test -f "$SOURCE_ROOT/pramagent/hook_integrity.json"
install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$STATE_ROOT"
rm -rf "$INSTALL_ROOT/pramagent" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/plugins"
cp -R "$SOURCE_ROOT/pramagent" "$SOURCE_ROOT/scripts" "$SOURCE_ROOT/plugins" "$INSTALL_ROOT/"
chown -R root:root "$INSTALL_ROOT" "$STATE_ROOT"
find "$INSTALL_ROOT" -type d -exec chmod 0755 {} \;
find "$INSTALL_ROOT" -type f -exec chmod 0444 {} \;
chmod 0755 "$INSTALL_ROOT/scripts/hook_bootstrap.py"

cat > /etc/pramagent-hook-boundary.env <<EOF
PRAMAGENT_HOOK_STATE_PATH=$STATE_ROOT/hook-config.json
PRAMAGENT_HOOK_ADMIN_AUDIT_DB=$STATE_ROOT/hook-admin-audit.db
EOF
chown root:root /etc/pramagent-hook-boundary.env
chmod 0400 /etc/pramagent-hook-boundary.env

for directory in .claude .gemini .codex; do
    path=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/$directory
    if [ -d "$path" ]; then
        chown -R root:"$AGENT_GROUP" "$path"
        find "$path" -type d -exec chmod 0550 {} \;
        find "$path" -type f -exec chmod 0440 {} \;
    fi
done

echo "protected runtime: $INSTALL_ROOT"
echo "protected state:   $STATE_ROOT"
echo "agent group:       $AGENT_GROUP (read/execute only)"
echo "root remains able to change the deployment and is outside this boundary"
