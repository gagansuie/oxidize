import sharp from 'sharp';
import { readFileSync, mkdirSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const svgPath = join(rootDir, 'public/app_icon.svg');
const iconsDir = join(rootDir, 'src-tauri/icons');

const sizes = [
  { name: '32x32.png', size: 32 },
  { name: '64x64.png', size: 64 },
  { name: '128x128.png', size: 128 },
  { name: '128x128@2x.png', size: 256 },
  { name: 'icon.png', size: 512 },
  { name: 'StoreLogo.png', size: 50 },
  { name: 'Square30x30Logo.png', size: 30 },
  { name: 'Square44x44Logo.png', size: 44 },
  { name: 'Square71x71Logo.png', size: 71 },
  { name: 'Square89x89Logo.png', size: 89 },
  { name: 'Square107x107Logo.png', size: 107 },
  { name: 'Square142x142Logo.png', size: 142 },
  { name: 'Square150x150Logo.png', size: 150 },
  { name: 'Square284x284Logo.png', size: 284 },
  { name: 'Square310x310Logo.png', size: 310 },
];

const iosSizes = [
  { name: 'AppIcon-20x20@1x.png', size: 20 },
  { name: 'AppIcon-20x20@2x.png', size: 40 },
  { name: 'AppIcon-20x20@3x.png', size: 60 },
  { name: 'AppIcon-29x29@1x.png', size: 29 },
  { name: 'AppIcon-29x29@2x.png', size: 58 },
  { name: 'AppIcon-29x29@3x.png', size: 87 },
  { name: 'AppIcon-40x40@1x.png', size: 40 },
  { name: 'AppIcon-40x40@2x.png', size: 80 },
  { name: 'AppIcon-40x40@3x.png', size: 120 },
  { name: 'AppIcon-60x60@2x.png', size: 120 },
  { name: 'AppIcon-60x60@3x.png', size: 180 },
  { name: 'AppIcon-76x76@1x.png', size: 76 },
  { name: 'AppIcon-76x76@2x.png', size: 152 },
  { name: 'AppIcon-83.5x83.5@2x.png', size: 167 },
  { name: 'AppIcon-512@2x.png', size: 1024 },
];

const androidSizes = [
  { folder: 'mipmap-mdpi', size: 48 },
  { folder: 'mipmap-hdpi', size: 72 },
  { folder: 'mipmap-xhdpi', size: 96 },
  { folder: 'mipmap-xxhdpi', size: 144 },
  { folder: 'mipmap-xxxhdpi', size: 192 },
];

async function generateIcons() {
  const svgBuffer = readFileSync(svgPath);

  // Generate main icons
  for (const { name, size } of sizes) {
    const output = join(iconsDir, name);
    await sharp(svgBuffer, { density: 300 })
      .resize(size, size)
      .png()
      .toFile(output);
    console.log(`Created ${name}`);
  }

  // Generate iOS icons
  const iosDir = join(iconsDir, 'ios');
  if (!existsSync(iosDir)) mkdirSync(iosDir, { recursive: true });

  for (const { name, size } of iosSizes) {
    const output = join(iosDir, name);
    await sharp(svgBuffer, { density: 300 })
      .resize(size, size)
      .png()
      .toFile(output);
    console.log(`Created ios/${name}`);
  }

  // Generate Android icons
  const androidDir = join(iconsDir, 'android');
  for (const { folder, size } of androidSizes) {
    const folderPath = join(androidDir, folder);
    if (!existsSync(folderPath)) mkdirSync(folderPath, { recursive: true });

    // ic_launcher.png
    await sharp(svgBuffer, { density: 300 })
      .resize(size, size)
      .png()
      .toFile(join(folderPath, 'ic_launcher.png'));

    // ic_launcher_round.png
    await sharp(svgBuffer, { density: 300 })
      .resize(size, size)
      .png()
      .toFile(join(folderPath, 'ic_launcher_round.png'));

    // ic_launcher_foreground.png (larger for adaptive icons)
    const fgSize = Math.round(size * 1.5);
    await sharp(svgBuffer, { density: 300 })
      .resize(fgSize, fgSize)
      .png()
      .toFile(join(folderPath, 'ic_launcher_foreground.png'));

    console.log(`Created android/${folder}/*`);
  }

  console.log('Done! All icons generated with transparent backgrounds.');
}

generateIcons().catch(console.error);
