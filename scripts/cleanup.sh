#!/bin/bash

BUILD_DIR="dist"
NODE_MODULES_DIR="node_modules"
LOGS_DIR="logs"
TEMP_FILES=("*.log" "*.tmp" "*.cache")

cleanup() {
  echo "Cleaning up..."

  if [ -d "$BUILD_DIR" ]; then
    echo "Removing $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
  fi

  if [ -d "$NODE_MODULES_DIR" ]; then
    echo "Removing $NODE_MODULES_DIR..."
    rm -rf "$NODE_MODULES_DIR"
  fi

  if [ -d "$LOGS_DIR" ]; then
    echo "Removing $LOGS_DIR..."
    rm -rf "$LOGS_DIR"
  fi

  for pattern in "${TEMP_FILES[@]}"; do
    echo "Removing files matching pattern: $pattern"
    find . -name "$pattern" -exec rm -f {} +
  done

  echo "Cleanup completed."
}

cleanup

