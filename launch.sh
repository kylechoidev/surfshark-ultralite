#!/usr/bin/env bash
# SurfShark Ultra-Lite Standalone App Launcher (LINE LITE-style dedicated window)
DIR="$(dirname "$(readlink -f "$0")")"
PORT="${SURFSHARK_WEBUI_PORT:-8777}"
APP_URL="http://127.0.0.1:$PORT"
WM_CLASS="SurfsharkUltraLite"

# 1. Ensure backend service is running
if ! curl -s --max-time 1 "$APP_URL/api/state" >/dev/null 2>&1; then
    systemctl --user start surfshark-webui.service >/dev/null 2>&1 || (setsid python3 "$DIR/app.py" >/dev/null 2>&1 &)
    for _ in {1..15}; do
        if curl -s --max-time 1 "$APP_URL/api/state" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
fi

# 2. Single-instance check: if window is already open, focus it
if command -v wmctrl >/dev/null 2>&1; then
    if wmctrl -l -x 2>/dev/null | grep -i "$WM_CLASS" >/dev/null; then
        wmctrl -x -a "$WM_CLASS" 2>/dev/null
        exit 0
    fi
fi

# 3. Launch dedicated standalone app window
USER_DATA_DIR="$HOME/.config/surfshark-webapp"
mkdir -p "$USER_DATA_DIR/Default"
touch "$USER_DATA_DIR/First Run" "$USER_DATA_DIR/EULA Accepted" 2>/dev/null

if command -v chromium >/dev/null 2>&1; then
    setsid chromium \
        --app="$APP_URL" \
        --class="$WM_CLASS" \
        --name="$WM_CLASS" \
        --user-data-dir="$USER_DATA_DIR" \
        --window-size=740,820 \
        --no-first-run \
        --no-default-browser-check \
        --disable-features=Translate,SpareRendererForSitePerProcess \
        --password-store=basic \
        >/dev/null 2>&1 &
elif command -v brave-origin >/dev/null 2>&1; then
    setsid brave-origin \
        --app="$APP_URL" \
        --class="$WM_CLASS" \
        --name="$WM_CLASS" \
        --user-data-dir="$USER_DATA_DIR" \
        --window-size=740,820 \
        --no-first-run \
        --no-default-browser-check \
        >/dev/null 2>&1 &
else
    xdg-open "$APP_URL" >/dev/null 2>&1 &
fi

exit 0

