#!/usr/bin/env bash
# ippeek systemd one-click manager: install | update | check | uninstall
# https://github.com/x-5/ippeek
set -euo pipefail

APP="ippeek"
REPO="${IPPEEK_REPO:-x-5/ippeek}"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
ENV_FILE="${CONF_DIR}/${APP}.env"
META_FILE="${CONF_DIR}/meta.env"
UNIT="/etc/systemd/system/${APP}.service"

VARIANT="" VERSION="latest" LISTEN=":8080" TOKEN=""
QUIET_DROPS="" MIRROR="" LOCAL_BIN="" KEEP_CONFIG="false"
TMP_DIR=""

trap 'rm -rf "${TMP_DIR:-}"' EXIT

die()  { printf '[ERR] %s\n' "$*" >&2; exit 1; }
info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }

usage() {
	cat <<'EOF'
Usage: sudo bash install.sh <install|update|check|uninstall> [options]

Options:
  --token <secret[,old]>         API token(s), auto-generated if omitted
  --listen <addr>                Listen address (default: :8080)
  --variant <tiny-upx|tiny|std>  Variant (default: tiny-upx, tiny on riscv64)
  --version <vX.Y.Z|latest>      Release tag (default: latest)
  --quiet-drops                  Suppress 444 drop logs
  --mirror <url-prefix>          GitHub download proxy prefix
  --local-bin <path>             Install/update from local binary
  --keep-config                  Keep /etc/ippeek on uninstall
EOF
}

need_root()    { [ "${EUID:-$(id -u)}" -eq 0 ] || die "Run as root (use sudo)."; }
need_systemd() { command -v systemctl >/dev/null 2>&1 || die "systemctl not found."; }
read_kv()      { [ -r "$1" ] && sed -n "s/^$2=//p" "$1" | head -n 1 || true; }

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64)    echo "linux-amd64" ;;
		aarch64|arm64)   echo "linux-arm64" ;;
		armv7*|armv7l)   echo "linux-armv7" ;;
		armv6*|armv6l)   echo "linux-armv6" ;;
		mips)            echo "linux-mips-softfloat" ;;
		mipsel|mipsle)   echo "linux-mipsle-softfloat" ;;
		riscv64)         echo "linux-riscv64" ;;
		*) die "Unsupported arch: $(uname -m)" ;;
	esac
}

pick_variant() {
	local v="${1:-}" arch="$2"
	if [ -z "${v}" ]; then
		if [ "${arch}" = "linux-riscv64" ]; then v="tiny"; else v="tiny-upx"; fi
	fi
	case "${v}" in
		std|tiny|tiny-upx) ;;
		*) die "Invalid --variant: ${v}" ;;
	esac
	if [ "${v}" = "tiny-upx" ] && [ "${arch}" = "linux-riscv64" ]; then v="tiny"; fi
	echo "${v}"
}

http_get() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 10 --max-time 120 "$@"
	elif command -v wget >/dev/null 2>&1; then
		if [ "$1" = "-o" ]; then wget -q --timeout=120 -O "$2" "$3"; else wget -qO- --timeout=30 "$1"; fi
	else
		die "curl or wget is required."
	fi
}

resolve_tag() {
	if [ "${VERSION}" != "latest" ]; then echo "${VERSION}"; return; fi
	local tag
	tag="$(http_get "https://api.github.com/repos/${REPO}/releases/latest" \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "${tag}" ] || die "Failed to fetch latest tag from ${REPO}"
	echo "${tag}"
}

gen_token() {
	if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16
	else od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; fi
}

loopback_url() {
	case "$1" in
		:*)        echo "http://127.0.0.1$1" ;;
		0.0.0.0:*) echo "http://127.0.0.1:${1#0.0.0.0:}" ;;
		"[::]:"*)  echo "http://[::1]:${1#\[::\]:}" ;;
		*)         echo "http://$1" ;;
	esac
}

install_bin() {
	local arch="$1" tag="$2" variant="$3"
	TMP_DIR="$(mktemp -d)"
	local dst="${TMP_DIR}/${APP}"

	if [ -n "${LOCAL_BIN}" ]; then
		[ -f "${LOCAL_BIN}" ] || die "Local binary not found: ${LOCAL_BIN}"
		cp "${LOCAL_BIN}" "${dst}"
	else
		local asset="${APP}-${variant}-${arch}"
		local base="${MIRROR}https://github.com/${REPO}/releases/download/${tag}"
		info "Downloading ${asset} (${tag})..."
		http_get -o "${dst}" "${base}/${asset}"
		if command -v sha256sum >/dev/null 2>&1 && http_get -o "${TMP_DIR}/checksums.txt" "${base}/checksums.txt" 2>/dev/null; then
			local want got
			want="$(awk -v f="${asset}" '$2==f || $2=="*"f {print $1; exit}' "${TMP_DIR}/checksums.txt")"
			if [ -n "${want}" ]; then
				got="$(sha256sum "${dst}" | awk '{print $1}')"
				[ "${want}" = "${got}" ] || die "SHA256 mismatch for ${asset}"
				ok "SHA256 verified"
			fi
		fi
	fi

	install -m 0755 "${dst}" "${BIN}.new"
	mv -f "${BIN}.new" "${BIN}"
	ok "Installed ${BIN} ($(du -h "${BIN}" | awk '{print $1}'))"
}

write_unit() {
	cat > "${UNIT}" <<EOF
[Unit]
Description=ippeek IP API Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP}
Group=${APP}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN}
Restart=on-failure
RestartSec=3s
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "${UNIT}"
	systemctl daemon-reload
}

self_check() {
	local listen tok first_tok escaped url rc=0 resp="" i
	listen="$(read_kv "${ENV_FILE}" IPPEEK_LISTEN)"
	tok="$(read_kv "${ENV_FILE}" IPPEEK_TOKEN)"
	first_tok="$(printf '%s\n' "${tok}" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF{print;exit}')"
	url="$(loopback_url "${listen:-:8080}")"

	command -v curl >/dev/null 2>&1 || { info "curl not found; skipping HTTP self-check."; return 0; }
	[ -n "${first_tok}" ] || die "IPPEEK_TOKEN is empty in ${ENV_FILE}"

	escaped="${first_tok//\\/\\\\}"
	escaped="${escaped//\"/\\\"}"

	for i in 1 2 3 4 5 6; do
		if resp="$(printf 'url = "%s/ip?token=%s&v=4&iface=lo&source=local"\n' "${url}" "${escaped}" | curl -fsSg --max-time 2 -K - 2>/dev/null)" && [ "${resp}" = "127.0.0.1" ]; then
			break
		fi
		sleep 0.5
	done
	if [ "${resp}" != "127.0.0.1" ]; then
		journalctl -u "${APP}" -n 20 --no-pager 2>/dev/null || true
		die "Service is not responding on ${url} (check logs above)"
	fi
	ok "API Auth: PASS (${url}/ip -> 127.0.0.1)"

	curl -sSg --max-time 2 "${url}/" >/dev/null 2>&1 || rc=$?
	if [ "${rc}" -eq 52 ]; then
		ok "444 Drop: PASS (GET / -> empty reply, exit 52)"
	else
		die "444 Drop: unexpected curl exit ${rc} on GET ${url}/"
	fi
}

cmd_install() {
	need_root; need_systemd
	local arch variant tag gen="false"
	arch="$(detect_arch)"
	variant="$(pick_variant "${VARIANT}" "${arch}")"
	if [ -z "${TOKEN}" ]; then TOKEN="$(gen_token)"; gen="true"; fi
	if [ -n "${LOCAL_BIN}" ]; then tag="${VERSION}"; else tag="$(resolve_tag)"; fi

	getent group "${APP}" >/dev/null 2>&1 || groupadd --system "${APP}"
	if ! id -u "${APP}" >/dev/null 2>&1; then
		local nologin="/usr/sbin/nologin"
		[ -x "${nologin}" ] || nologin="/sbin/nologin"
		[ -x "${nologin}" ] || nologin="/bin/false"
		useradd --system -g "${APP}" --no-create-home --shell "${nologin}" "${APP}"
	fi

	install_bin "${arch}" "${tag}" "${variant}"

	mkdir -p "${CONF_DIR}"
	chown "root:${APP}" "${CONF_DIR}"
	chmod 0750 "${CONF_DIR}"
	{
		printf 'IPPEEK_LISTEN=%s\n' "${LISTEN}"
		printf 'IPPEEK_TOKEN=%s\n' "${TOKEN}"
		if [ -n "${QUIET_DROPS}" ]; then printf 'IPPEEK_QUIET_DROPS=true\n'; fi
	} > "${ENV_FILE}"
	chown "root:${APP}" "${ENV_FILE}"
	chmod 0640 "${ENV_FILE}"
	printf 'REPO=%s\nVARIANT=%s\nVERSION=%s\n' "${REPO}" "${variant}" "${tag}" > "${META_FILE}"
	chmod 0644 "${META_FILE}"

	write_unit
	systemctl enable "${APP}" >/dev/null 2>&1 || true
	systemctl restart "${APP}"

	self_check
	ok "Deployed ${APP} (${tag}, ${variant}) listening on ${LISTEN}"
	if [ "${gen}" = "true" ]; then printf '  Token  : %s\n' "${TOKEN}"; fi
	printf '  Config : %s\n' "${ENV_FILE}"
	printf '  Test   : curl "%s/ip?token=<TOKEN>&v=4"\n' "$(loopback_url "${LISTEN}")"
}

cmd_update() {
	need_root; need_systemd
	[ -f "${ENV_FILE}" ] || die "${ENV_FILE} not found; run install first."
	local arch meta_var meta_ver variant tag
	arch="$(detect_arch)"
	meta_var="$(read_kv "${META_FILE}" VARIANT)"
	meta_ver="$(read_kv "${META_FILE}" VERSION)"
	variant="$(pick_variant "${VARIANT:-${meta_var}}" "${arch}")"
	if [ -n "${LOCAL_BIN}" ]; then tag="${VERSION}"; else tag="$(resolve_tag)"; fi

	if [ -z "${LOCAL_BIN}" ] && [ "${tag}" = "${meta_ver}" ] && [ "${variant}" = "${meta_var}" ]; then
		ok "Already up to date (${tag}, ${variant})."
		return
	fi

	install_bin "${arch}" "${tag}" "${variant}"
	printf 'REPO=%s\nVARIANT=%s\nVERSION=%s\n' "${REPO}" "${variant}" "${tag}" > "${META_FILE}"
	write_unit
	systemctl restart "${APP}"
	self_check
	ok "Updated to ${tag} (${variant})."
}

cmd_check() {
	need_systemd
	if [ -x "${BIN}" ]; then
		ok "Binary : ${BIN} ($(du -h "${BIN}" | awk '{print $1}'), $("${BIN}" -version 2>/dev/null || echo unknown))"
	else
		die "Binary missing: ${BIN}"
	fi
	info "Meta   : version=$(read_kv "${META_FILE}" VERSION) variant=$(read_kv "${META_FILE}" VARIANT)"
	info "Service: active=$(systemctl is-active "${APP}" 2>/dev/null || true) enabled=$(systemctl is-enabled "${APP}" 2>/dev/null || true)"
	if command -v ss >/dev/null 2>&1; then
		ss -tlnp 2>/dev/null | grep -E "State|${APP}" || true
	fi
	if [ -r "${ENV_FILE}" ]; then
		self_check
	else
		info "Run with sudo for authenticated loopback self-check."
	fi
	journalctl -u "${APP}" -n 10 --no-pager 2>/dev/null || true
}

cmd_uninstall() {
	need_root; need_systemd
	systemctl disable --now "${APP}" 2>/dev/null || true
	rm -f "${UNIT}" "${BIN}"
	systemctl daemon-reload
	if [ "${KEEP_CONFIG}" != "true" ]; then rm -rf "${CONF_DIR}"; fi
	id -u "${APP}" >/dev/null 2>&1 && userdel "${APP}" 2>/dev/null || true
	getent group "${APP}" >/dev/null 2>&1 && groupdel "${APP}" 2>/dev/null || true
	ok "Uninstalled ${APP}."
}

cmd="${1:-}"
[ -n "${cmd}" ] || { usage; exit 1; }
shift
case "${cmd}" in
	-h|--help|help) usage; exit 0 ;;
	install|update|check|status|uninstall) ;;
	*) die "Unknown command: ${cmd}" ;;
esac

while [ $# -gt 0 ]; do
	case "$1" in
		--token)       [ $# -ge 2 ] || die "$1 requires a value"; TOKEN="$2"; shift 2 ;;
		--listen)      [ $# -ge 2 ] || die "$1 requires a value"; LISTEN="$2"; shift 2 ;;
		--variant)     [ $# -ge 2 ] || die "$1 requires a value"; VARIANT="$2"; shift 2 ;;
		--version)     [ $# -ge 2 ] || die "$1 requires a value"; VERSION="$2"; shift 2 ;;
		--mirror)      [ $# -ge 2 ] || die "$1 requires a value"; MIRROR="$2"; shift 2 ;;
		--local-bin)   [ $# -ge 2 ] || die "$1 requires a value"; LOCAL_BIN="$2"; shift 2 ;;
		--quiet-drops) QUIET_DROPS="true"; shift ;;
		--keep-config) KEEP_CONFIG="true"; shift ;;
		-h|--help)     usage; exit 0 ;;
		*) die "Unknown option: $1" ;;
	esac
done

case "${cmd}" in
	install)      cmd_install ;;
	update)       cmd_update ;;
	check|status) cmd_check ;;
	uninstall)    cmd_uninstall ;;
esac
