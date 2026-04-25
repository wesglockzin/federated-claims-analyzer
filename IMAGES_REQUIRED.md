# Required Images for UI

The application requires two images to be placed in the `static/` directory:

## 1. Capitol Background Image
- **Filename**: `capitol-background.jpg`
- **Path**: `static/capitol-background.jpg`
- **Description**: US Capitol building background image
- **Source**: User-provided Capitol dome photograph
- **Usage**: Background image for all pages (login, main app, admin)

## 2. US Senate Seal
- **Filename**: `senate-seal.png`
- **Path**: `static/senate-seal.png`
- **Description**: Official US Senate seal
- **Source**: User-provided Senate seal circular logo
- **Usage**: Favicon for browser tab, app icon

## Deployment Steps

Before deploying the updated application:

1. Save the Capitol background image as `static/capitol-background.jpg`
2. Save the Senate seal as `static/senate-seal.png`
3. Verify both files exist:
   ```bash
   ls -la static/
   # Should show:
   # - capitol-background.jpg
   # - senate-seal.png
   ```
4. Then rebuild and deploy the container

## Image Specifications

### Capitol Background
- Format: JPEG recommended (for smaller file size)
- Resolution: At least 1920x1080 pixels
- File size: Keep under 500KB if possible

### Senate Seal
- Format: PNG (for transparency support)
- Resolution: At least 512x512 pixels (for high-DPI displays)
- Background: Transparent or white

## Current Status

⚠️ **ACTION REQUIRED**: These images need to be manually placed in the `static/` directory before deployment.

The HTML templates are already configured to reference these images:
- All pages use `/static/senate-seal.png` for favicon
- All pages use `/static/capitol-background.jpg` for background
- Background has semi-transparent overlay for readability

<!-- CODEX_WORK_UPDATE_START -->
## Codex Work Participation Update (2026-03-20)
- Performed a repository-wide Markdown refresh to keep documentation aligned.
- Added/updated this note during the current maintenance task.
<!-- CODEX_WORK_UPDATE_END -->
