# Tauri icons

These binary icon assets (`32x32.png`, `128x128.png`, `128x128@2x.png`,
`icon.icns`, `icon.ico`) are **generated** and intentionally git-ignored.

Generate them from the canonical SVG logo:

```bash
cd desktop
npx tauri icon ../frontend/img/icon-192.svg src-tauri/icons
```

`tauri build` requires these to exist; `desktop/build_desktop.bat` runs the
icon generation automatically if they are missing.
