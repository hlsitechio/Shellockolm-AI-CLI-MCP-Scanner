# How to Add Banner Image to GitHub Repository

## Step 1: Prepare the Image

1. Save your banner image as `banner.png` in the repository root or in a `docs/images/` folder
2. Recommended dimensions: 1280x640px (2:1 ratio)
3. File size: Under 1MB for fast loading
4. Format: PNG or JPG

## Step 2: Add Image to Repository

```bash
# Create images directory
mkdir -p docs/images

# Copy your image (replace with your actual image path)
cp /path/to/your/banner.png docs/images/banner.png

# Add to git
git add docs/images/banner.png
git commit -m "Add repository banner image"
git push origin main
```

## Step 3: Update README.md

Add the image at the very top of your README, right after the title:

```markdown
# 🛡️ CVE-2025-55182 Security Tools

![CVE-2025-55182 Security Tools Banner](./docs/images/banner.png)

<div align="center">

**Complete toolset for detecting and patching CVE-2025-55182 (React2Shell)**
...
```

## Alternative: Use GitHub's Social Preview

GitHub has a built-in social preview image feature:

1. Go to your repository on GitHub
2. Click "Settings"
3. Scroll to "Social preview" section
4. Click "Edit"
5. Upload your banner image
6. Click "Save"

This image will appear when your repo is shared on social media!

## Tips for Great Banner Images

- Use high contrast colors
- Include your project name clearly
- Show key features or benefits
- Use professional fonts
- Include relevant icons or illustrations
- Make it visually striking to increase stars!

## Current Banner Ideas for CVE-2025-55182 Tools

Suggested elements to include:
- 🛡️ Security shield icon
- "CVE-2025-55182" prominently
- "CVSS 10.0" badge
- "100% Success Rate" badge
- Tech logos: React, Next.js, Python
- Color scheme: Red (danger) + Green (security) + Blue (tech)
