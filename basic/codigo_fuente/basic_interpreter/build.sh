#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$APP_DIR/../flipper-sdk"
TARGET_DIR="$SDK_DIR/applications_user/basic_interpreter"

if [ ! -d "$SDK_DIR" ]; then
  echo "No se encontró flipper-sdk en: $SDK_DIR"
  exit 1
fi

if [ ! -d "$APP_DIR" ]; then
  echo "No se encontró la app en: $APP_DIR"
  exit 1
fi

echo "Copiando app BASIC Interpreter al SDK de Flipper..."
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cp -r "$APP_DIR"/* "$TARGET_DIR"

echo "App copiada a: $TARGET_DIR"
cat <<'EOF'
Para compilar el paquete .fap:
  cd "$SDK_DIR"
  ./fbt TARGET_HW=DEV fap_dist
EOF
