#!/usr/bin/env bash
# ippeek systemd one-click lifecycle manager: install | update | check | uninstall
# Repo: https://github.com/x-5/ippeek

set -euo pipefail

APP_NAME="ippeek"
DEFAULT_REPO="x-5/ippeek"
BIN_PATH="/usr/local/bin/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
ENV_FILE="${CONF_DIR}/${APP_NAME}.env"
META_FILE="${CONF_DIR}/meta.env"
UNIT_FILE="/etc/systemd/system/${APP_NAME}.service"
SVC_USER="${APP_NAME}"

REPO="${DEFAULT_REPO}"
REPO_SET="false"
VARIANT=""
VERSION="latest"
LISTEN=":8080"
TOKEN=""
CACHE_TTL="60s"
PROBE_TIMEOUT="3s"
V4_PROBES=""
V6_PROBES=""
TRUST_PROXY=""
LOCAL_BIN=""
MIRROR=""
KEEP_CONFIG="false"

info()  { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[OK]\033[0m   %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[ERR]\033[0m  %s\n' "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() {
	cat <<'EOF'
Usage:
  sudo bash install.sh <install|update|check|uninstall> [options]

Commands:
  install     Download binary, write env/systemd unit, enable and start ippeek
  update      Update ippeek binary to latest or specified version (keeps config)
  check       Verify systemd status, binary info, logs, and loopback 444/200 checks
  uninstall   Stop, disable, and remove ippeek service, binary, user, and config

Options:
  --variant <tiny-upx|tiny|std>  Binary variant (default: tiny-upx, or tiny on riscv64)
  --version <vX.Y.Z|latest>      Release tag to install/update (default: latest)
  --repo <owner/repo>            GitHub repository (default: x-5/ippeek)
  --mirror <url-prefix>          Optional download proxy prefix (e.g. https://ghfast.top/)
  --local-bin <path>             Install/update from a local binary instead of downloading
  --listen <addr>                Listen address (default: :8080)
  --token <secret>               API token (auto-generated on install if omitted)
  --cache-ttl <duration>         External probe cache TTL (default: 60s)
  --probe-timeout <duration>     External probe timeout (default: 3s)
  --v4-probes <csv>              Custom IPv4 probe URLs (comma-separated)
  --v6-probes <csv>              Custom IPv6 probe URLs (comma-separated)
  --trust-proxy                  Trust X-Forwarded-For / X-Real-IP headers
  --keep-config                  Preserve /etc/ippeek during uninstall
  -h, --help                     Show this help

Examples:
  sudo bash install.sh install --token my-secret --listen :8080
  sudo bash install.sh install --variant std --token my-secret
  sudo bash install.sh update
  sudo bash install.sh check
  sudo bash install.sh uninstall
EOF
}

require_root() {
	if [ "${EUID:-$(id -u)}" -ne 0 ]; then
		die "Please run as root (use sudo)."
	fi
}

require_systemd() {
	command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this script requires systemd."
}

detect_arch() {
	local machine
	machine="$(uname -m)"
	case "${machine}" in
		x86_64|amd64)       echo "linux-amd64" ;;
		aarch64|arm64)      echo "linux-arm64" ;;
		armv7*|armv7l)      echo "linux-armv7" ;;
		armv6*|armv6l)      echo "linux-armv6" ;;
		mips)               echo "linux-mips-softfloat" ;;
		mipsel|mipsle)      echo "linux-mipsle-softfloat" ;;
		riscv64)            echo "linux-riscv64" ;;
		*) die "Unsupported architecture: ${machine}" ;;
	esac
}

default_variant_for_arch() {
	local arch="$1"
	if [ "${arch}" = "linux-riscv64" ]; then
		echo "tiny"
	else
		echo "tiny-upx"
	fi
}

validate_variant() {
	local v="$1" arch="$2"
	case "${v}" in
		std|tiny|tiny-upx) ;;
		*) die "Invalid --variant '${v}' (expected: tiny-upx, tiny, or std)" ;;
	esac
	if [ "${v}" = "tiny-upx" ] && [ "${arch}" = "linux-riscv64" ]; then
		warn "tiny-upx is not available on riscv64; switching to 'tiny'."
		VARIANT="tiny"
	fi
}

fetch_text() {
	local url="$1"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 10 --max-time 30 "${url}"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- --timeout=30 "${url}"
	else
		die "Neither curl nor wget is installed."
	fi
}

download_file() {
	local url="$1" dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 10 --max-time 120 -o "${dest}" "${url}"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --timeout=120 -O "${dest}" "${url}"
	else
		die "Neither curl nor wget is installed."
	fi
}

resolve_version() {
	if [ "${VERSION}" != "latest" ]; then
		echo "${VERSION}"
		return
	fi
	local api_url="https://api.github.com/repos/${REPO}/releases/latest"
	local tag
	tag="$(fetch_text "${api_url}" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "${tag}" ] || die "Failed to resolve latest release tag from ${api_url}"
	echo "${tag}"
}

generate_token() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 16
	elif [ -r /dev/urandom ]; then
		od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
	else
		die "Cannot generate random token; please pass --token <secret>."
	fi
}

install_binary() {
	local arch="$1" tag="$2" variant="$3"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	trap 'rm -rf "${tmp_dir}"' RETURN

	local target_bin="${tmp_dir}/${APP_NAME}"

	if [ -n "${LOCAL_BIN}" ]; then
		[ -f "${LOCAL_BIN}" ] || die "Local binary not found: ${LOCAL_BIN}"
		info "Using local binary: ${LOCAL_BIN}"
		cp "${LOCAL_BIN}" "${target_bin}"
	else
		local asset="${APP_NAME}-${variant}-${arch}"
		local base_url="${MIRROR}https://github.com/${REPO}/releases/download/${tag}"
		local bin_url="${base_url}/${asset}"
		local sum_url="${base_url}/checksums.txt"

		info "Downloading ${asset} (${tag})..."
		download_file "${bin_url}" "${target_bin}"

		if command -v sha256sum >/dev/null 2>&1; then
			if download_file "${sum_url}" "${tmp_dir}/checksums.txt" 2>/dev/null; then
				local expected actual
				expected="$(awk -v f="${asset}" '$2 == f || $2 == "*"f {print $1; exit}' "${tmp_dir}/checksums.txt")"
				if [ -n "${expected}" ]; then
					actual="$(sha256sum "${target_bin}" | awk '{print $1}')"
					if [ "${expected}" != "${actual}" ]; then
						die "SHA256 mismatch for ${asset} (expected ${expected}, got ${actual})"
					fi
					ok "SHA256 verified (${actual:0:12}...)"
				else
					warn "Asset ${asset} not listed in checksums.txt; skipping checksum verification."
				fi
			else
				warn "Could not download checksums.txt; skipping checksum verification."
			fi
		fi
	fi

	chmod 0755 "${target_bin}"
	install -m 0755 "${target_bin}" "${BIN_PATH}.new"
	mv -f "${BIN_PATH}.new" "${BIN_PATH}"
	ok "Installed binary to ${BIN_PATH} ($(du -h "${BIN_PATH}" | awk '{print $1}'))"
}

ensure_service_user() {
	if ! id -u "${SVC_USER}" >/dev/null 2>&1; then
		local nologin="/usr/sbin/nologin"
		[ -x "${nologin}" ] || nologin="/sbin/nologin"
		[ -x "${nologin}" ] || nologin="/bin/false"
		useradd --system --no-create-home --shell "${nologin}" "${SVC_USER}"
		ok "Created system user '${SVC_USER}'"
	fi
}

write_config_files() {
	local tag="$1" variant="$2" arch="$3"
	install -d -m 0750 -o root -g "${SVC_USER}" "${CONF_DIR}"

	{
		echo "IPPEEK_LISTEN=${LISTEN}"
		echo "IPPEEK_TOKEN=${TOKEN}"
		echo "IPPEEK_CACHE_TTL=${CACHE_TTL}"
		echo "IPPEEK_PROBE_TIMEOUT=${PROBE_TIMEOUT}"
		[ -n "${V4_PROBES}" ]   && echo "IPPEEK_V4_PROBES=${V4_PROBES}"
		[ -n "${V6_PROBES}" ]   && echo "IPPEEK_V6_PROBES=${V6_PROBES}"
		[ -n "${TRUST_PROXY}" ] && echo "IPPEEK_TRUST_PROXY=${TRUST_PROXY}"
	} > "${ENV_FILE}"
	chown root:"${SVC_USER}" "${ENV_FILE}"
	chmod 0640 "${ENV_FILE}"

	{
		echo "REPO=${REPO}"
		echo "VARIANT=${variant}"
		echo "ARCH=${arch}"
		echo "VERSION=${tag}"
	} > "${META_FILE}"
	chmod 0644 "${META_FILE}"
}

write_systemd_unit() {
	cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=Ultra-minimal IP API Server (${APP_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=on-failure
RestartSec=3s
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryMax=64M
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "${UNIT_FILE}"
	systemctl daemon-reload
}

listen_to_loopback_url() {
	local addr="$1"
	case "${addr}" in
		:*)
			echo "http://127.0.0.1${addr}" ;;
		0.0.0.0:*)
			echo "http://127.0.0.1:${addr#0.0.0.0:}" ;;
		"[::]:"*)
			echo "http://[::1]:${addr#\[::\]:}" ;;
		*)
			echo "http://${addr}" ;;
	esac
}

read_kv() {
	local file="$1" key="$2"
	sed -n "s/^${key}=//p" "${file}" | head -n 1
}

cmd_install() {
	require_root
	require_systemd

	local arch
	arch="$(detect_arch)"
	[ -n "${VARIANT}" ] || VARIANT="$(default_variant_for_arch "${arch}")"
	validate_variant "${VARIANT}" "${arch}"

	local generated_token="false"
	if [ -z "${TOKEN}" ]; then
		TOKEN="$(generate_token)"
		generated_token="true"
	fi

	local tag="${VERSION}"
	if [ -z "${LOCAL_BIN}" ]; then
		tag="$(resolve_version)"
	fi

	info "Installing ${APP_NAME} (version=${tag}, variant=${VARIANT}, arch=${arch})..."
	ensure_service_user
	install_binary "${arch}" "${tag}" "${VARIANT}"
	write_config_files "${tag}" "${VARIANT}" "${arch}"
	write_systemd_unit

	systemctl enable --now "${APP_NAME}"
	sleep 1

	if systemctl is-active --quiet "${APP_NAME}"; then
		ok "${APP_NAME}.service is active and enabled."
	else
		err "${APP_NAME}.service failed to start. Recent logs:"
		journalctl -u "${APP_NAME}" -n 20 --no-pager || true
		exit 1
	fi

	local base_url
	base_url="$(listen_to_loopback_url "${LISTEN}")"
	echo ""
	ok "Deployment complete!"
	echo "  Listen  : ${LISTEN}"
	echo "  Config  : ${ENV_FILE}"
	if [ "${generated_token}" = "true" ]; then
		echo "  Token   : ${TOKEN} (auto-generated, save it safely)"
	fi
	echo "  Example : curl \"${base_url}/ip?token=<TOKEN>&v=4\""
	echo "  Check   : sudo bash $0 check"
}

cmd_update() {
	require_root
	require_systemd
	[ -f "${ENV_FILE}" ] || die "${ENV_FILE} not found. Run 'install' first."

	local meta_repo="" meta_variant="" meta_version="unknown" arch
	if [ -f "${META_FILE}" ]; then
		meta_repo="$(read_kv "${META_FILE}" REPO)"
		meta_variant="$(read_kv "${META_FILE}" VARIANT)"
		meta_version="$(read_kv "${META_FILE}" VERSION)"
		[ -n "${meta_version}" ] || meta_version="unknown"
	fi
	if [ "${REPO_SET}" != "true" ] && [ -n "${meta_repo}" ]; then
		REPO="${meta_repo}"
	fi
	arch="$(detect_arch)"
	[ -n "${VARIANT}" ] || VARIANT="${meta_variant:-$(default_variant_for_arch "${arch}")}"
	validate_variant "${VARIANT}" "${arch}"

	local target_tag="${VERSION}"
	if [ -z "${LOCAL_BIN}" ]; then
		target_tag="$(resolve_version)"
		if [ "${target_tag}" = "${meta_version}" ] && [ "${VARIANT}" = "${meta_variant}" ]; then
			ok "${APP_NAME} is already up to date (${meta_version}, variant=${VARIANT})."
			return
		fi
	fi

	info "Updating ${APP_NAME}: ${meta_version} (${meta_variant:-?}) -> ${target_tag} (${VARIANT}, ${arch})..."
	install_binary "${arch}" "${target_tag}" "${VARIANT}"

	{
		echo "REPO=${REPO}"
		echo "VARIANT=${VARIANT}"
		echo "ARCH=${arch}"
		echo "VERSION=${target_tag}"
	} > "${META_FILE}"

	systemctl restart "${APP_NAME}"
	sleep 1

	if systemctl is-active --quiet "${APP_NAME}"; then
		ok "Updated and restarted ${APP_NAME}.service (${target_tag}, variant=${VARIANT})."
	else
		err "Service failed to restart after update. Recent logs:"
		journalctl -u "${APP_NAME}" -n 20 --no-pager || true
		exit 1
	fi
}

cmd_check() {
	require_systemd

	echo "=== ${APP_NAME} Status ==="
	if [ -x "${BIN_PATH}" ]; then
		ok "Binary  : ${BIN_PATH} ($(du -h "${BIN_PATH}" | awk '{print $1}'))"
	else
		err "Binary  : missing (${BIN_PATH})"
	fi

	if [ -f "${META_FILE}" ]; then
		# shellcheck disable=SC1090
		. "${META_FILE}"
		info "Metadata: version=${VERSION:-?} variant=${VARIANT:-?} arch=${ARCH:-?} repo=${REPO:-?}"
	fi

	local active enabled
	active="$(systemctl is-active "${APP_NAME}" 2>/dev/null || true)"
	enabled="$(systemctl is-enabled "${APP_NAME}" 2>/dev/null || true)"
	if [ "${active}" = "active" ]; then
		ok "Service : active (enabled=${enabled})"
	else
		err "Service : ${active:-inactive} (enabled=${enabled})"
	fi

	if [ -r "${ENV_FILE}" ] && command -v curl >/dev/null 2>&1 && [ "${active}" = "active" ]; then
		local env_listen env_token base_url
		env_listen="$(sed -n 's/^IPPEEK_LISTEN=//p' "${ENV_FILE}" | head -n 1)"
		env_token="$(sed -n 's/^IPPEEK_TOKEN=//p' "${ENV_FILE}" | head -n 1)"
		base_url="$(listen_to_loopback_url "${env_listen:-:8080}")"

		# 1. Verify 444 connection-level drop (curl exit code 52 = Empty reply from server)
		local rc=0
		curl -sS --max-time 3 "${base_url}/" >/dev/null 2>&1 || rc=$?
		if [ "${rc}" -eq 52 ]; then
			ok "444 Drop: PASS (GET / returned empty reply, exit=52)"
		else
			warn "444 Drop: unexpected curl exit=${rc} for GET ${base_url}/"
		fi

		# 2. Verify authenticated loopback query without printing the token
		local resp
		if resp="$(curl -fsS --max-time 3 "${base_url}/ip?token=${env_token}&v=4&iface=lo&source=local" 2>/dev/null)"; then
			if [ "${resp}" = "127.0.0.1" ]; then
				ok "API Auth: PASS (GET /ip?iface=lo&source=local -> 127.0.0.1)"
			else
				warn "API Auth: unexpected body '${resp}'"
			fi
		else
			err "API Auth: FAILED to query ${base_url}/ip"
		fi
	elif [ ! -r "${ENV_FILE}" ]; then
		warn "Run with sudo to perform authenticated loopback self-check."
	fi

	echo ""
	echo "=== Recent Logs ==="
	journalctl -u "${APP_NAME}" -n 10 --no-pager 2>/dev/null || true
}

cmd_uninstall() {
	require_root
	require_systemd

	info "Uninstalling ${APP_NAME}..."
	if systemctl list-unit-files "${APP_NAME}.service" >/dev/null 2>&1; then
		systemctl disable --now "${APP_NAME}" 2>/dev/null || true
	fi
	if [ -f "${UNIT_FILE}" ]; then
		rm -f "${UNIT_FILE}"
		systemctl daemon-reload
		ok "Removed ${UNIT_FILE}"
	fi
	if [ -f "${BIN_PATH}" ]; then
		rm -f "${BIN_PATH}"
		ok "Removed ${BIN_PATH}"
	fi
	if [ "${KEEP_CONFIG}" = "true" ]; then
		warn "Preserved ${CONF_DIR} (--keep-config)"
	elif [ -d "${CONF_DIR}" ]; then
		rm -rf "${CONF_DIR}"
		ok "Removed ${CONF_DIR}"
	fi
	if id -u "${SVC_USER}" >/dev/null 2>&1; then
		userdel "${SVC_USER}" 2>/dev/null || true
		ok "Removed system user '${SVC_USER}'"
	fi
	ok "${APP_NAME} uninstalled cleanly."
}

main() {
	if [ $# -lt 1 ]; then
		usage
		exit 1
	fi

	local cmd="$1"
	shift

	case "${cmd}" in
		-h|--help|help)
			usage
			exit 0 ;;
		install|update|check|status|uninstall) ;;
		*)
			err "Unknown command: ${cmd}"
			usage
			exit 1 ;;
	esac

	while [ $# -gt 0 ]; do
		case "$1" in
			--variant)       VARIANT="${2:-}"; shift 2 ;;
			--version)       VERSION="${2:-}"; shift 2 ;;
			--repo)          REPO="${2:-}"; REPO_SET="true"; shift 2 ;;
			--mirror)        MIRROR="${2:-}"; shift 2 ;;
			--local-bin)     LOCAL_BIN="${2:-}"; shift 2 ;;
			--listen)        LISTEN="${2:-}"; shift 2 ;;
			--token)         TOKEN="${2:-}"; shift 2 ;;
			--cache-ttl)     CACHE_TTL="${2:-}"; shift 2 ;;
			--probe-timeout) PROBE_TIMEOUT="${2:-}"; shift 2 ;;
			--v4-probes)     V4_PROBES="${2:-}"; shift 2 ;;
			--v6-probes)     V6_PROBES="${2:-}"; shift 2 ;;
			--trust-proxy)   TRUST_PROXY="true"; shift ;;
			--keep-config)   KEEP_CONFIG="true"; shift ;;
			-h|--help)       usage; exit 0 ;;
			*) die "Unknown option: $1" ;;
		esac
	done

	case "${cmd}" in
		install)      cmd_install ;;
		update)       cmd_update ;;
		check|status) cmd_check ;;
		uninstall)    cmd_uninstall ;;
	esac
}

main "$@"
