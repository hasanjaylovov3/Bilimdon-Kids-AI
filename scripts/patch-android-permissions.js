import fs from "node:fs";
import path from "node:path";

const manifestPath = path.resolve("android/app/src/main/AndroidManifest.xml");
if (!fs.existsSync(manifestPath)) {
  throw new Error("Capacitor AndroidManifest.xml topilmadi: " + manifestPath);
}
let manifest = fs.readFileSync(manifestPath, "utf8");
const permissions = [
  "android.permission.INTERNET",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.MODIFY_AUDIO_SETTINGS"
];
for (const permission of permissions) {
  const declaration = '<uses-permission android:name="' + permission + '" />';
  if (!manifest.includes('android:name="' + permission + '"')) {
    manifest = manifest.replace(/<application\b/, declaration + "\n    <application");
  }
}
if (!manifest.includes('android:name="android.hardware.camera"')) {
  manifest = manifest.replace(/<application\b/, '<uses-feature android:name="android.hardware.camera" android:required="false" />\n    <application');
}
if (!manifest.includes('android:name="android.hardware.microphone"')) {
  manifest = manifest.replace(/<application\b/, '<uses-feature android:name="android.hardware.microphone" android:required="false" />\n    <application');
}
fs.writeFileSync(manifestPath, manifest);
console.log("Android manifest: CAMERA, RECORD_AUDIO va audio sozlamalari ruxsatlari qo‘shildi.");
